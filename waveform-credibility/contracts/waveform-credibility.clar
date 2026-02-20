;; Waveform Credibility Protocol

;; Constants

(define-constant CONTRACT-OWNER tx-sender)

;; Error codes
(define-constant ERR-NOT-AUTHORIZED        (err u100))
(define-constant ERR-ALREADY-REGISTERED   (err u101))
(define-constant ERR-NOT-REGISTERED       (err u102))
(define-constant ERR-INVALID-SCORE        (err u103))
(define-constant ERR-INVALID-DOMAIN       (err u104))
(define-constant ERR-ORACLE-NOT-FOUND     (err u105))
(define-constant ERR-SELF-ATTESTATION     (err u106))

;; Score boundaries (0 - 1000)
(define-constant MAX-SCORE u1000)
(define-constant MIN-SCORE u0)

;; Decay rate applied per epoch (in basis points, e.g. 50 = 0.5%)
(define-constant DECAY-RATE-BPS u50)

;; Registered domain identifiers
(define-constant DOMAIN-FINANCE     u1)
(define-constant DOMAIN-COMMERCE    u2)
(define-constant DOMAIN-GOVERNANCE  u3)
(define-constant DOMAIN-GENERAL     u4)

;; ---------------------------------------------------------------
;; Data Maps and Variables
;; ---------------------------------------------------------------

;; Tracks the last used profile ID
(define-data-var next-profile-id uint u1)

;; Maps principal -> profile ID
(define-map principal-to-id principal uint)

;; Core identity profile
(define-map profiles uint {
    owner:          principal,
    registered-at:  uint,          ;; block height at registration
    active:         bool
})

;; Domain-specific credibility scores per profile
;; score is stored as u0-u1000; last-update is the block height of last change
(define-map domain-scores { profile-id: uint, domain: uint } {
    score:          uint,
    last-update:    uint,
    event-count:    uint
})

;; Approved oracles that may submit score updates
(define-map approved-oracles principal bool)

;; Behavioral event log (profile-id, sequence-number) -> event details
(define-data-var next-event-seq uint u1)

(define-map wave-events uint {
    profile-id:     uint,
    domain:         uint,
    delta:          int,            ;; positive or negative score change
    submitted-by:   principal,
    block-height:   uint
})

;; Cross-chain portability: maps (cid, remote-address-hash) -> local profile-id
(define-map cross-chain-links { cid: uint, remote-hash: (buff 32) } uint)

;; ---------------------------------------------------------------
;; Private Helpers
;; ---------------------------------------------------------------

;; Validate that a domain code is recognised
(define-private (valid-domain (domain uint))
    (or
        (is-eq domain DOMAIN-FINANCE)
        (is-eq domain DOMAIN-COMMERCE)
        (is-eq domain DOMAIN-GOVERNANCE)
        (is-eq domain DOMAIN-GENERAL)
    )
)

;; Apply wave decay: score decreases by DECAY-RATE-BPS per elapsed block-epoch (1000 blocks).
;; Returns the decayed score, floored at MIN-SCORE.
(define-private (apply-decay (score uint) (last-update uint))
    (let (
        (elapsed    (- block-height last-update))
        (epochs     (/ elapsed u1000))
        (decay-amt  (/ (* score (* epochs DECAY-RATE-BPS)) u10000))
    )
        (if (> decay-amt score)
            MIN-SCORE
            (- score decay-amt)
        )
    )
)

;; Clamp a uint to [MIN-SCORE, MAX-SCORE]
(define-private (clamp-score (raw uint))
    (if (> raw MAX-SCORE)
        MAX-SCORE
        raw
    )
)

;; Apply a signed delta to a decayed score and clamp the result
(define-private (adjust-score (current uint) (last-update uint) (delta int))
    (let (
        (decayed    (apply-decay current last-update))
        (new-raw    (+ (to-int decayed) delta))
    )
        (if (< new-raw 0)
            MIN-SCORE
            (clamp-score (to-uint new-raw))
        )
    )
)

;; ---------------------------------------------------------------
;; Layer 1 - Wave Capture: Registration and Event Submission
;; ---------------------------------------------------------------

;; Register the calling principal as a new identity profile
(define-public (register)
    (let (
        (caller     tx-sender)
        (new-id     (var-get next-profile-id))
    )
        (asserts! (is-none (map-get? principal-to-id caller)) ERR-ALREADY-REGISTERED)

        (map-set principal-to-id caller new-id)
        (map-set profiles new-id {
            owner:          caller,
            registered-at:  block-height,
            active:         true
        })

        ;; Initialise scores for all domains at 0
        (map-set domain-scores { profile-id: new-id, domain: DOMAIN-FINANCE }    { score: u0, last-update: block-height, event-count: u0 })
        (map-set domain-scores { profile-id: new-id, domain: DOMAIN-COMMERCE }   { score: u0, last-update: block-height, event-count: u0 })
        (map-set domain-scores { profile-id: new-id, domain: DOMAIN-GOVERNANCE } { score: u0, last-update: block-height, event-count: u0 })
        (map-set domain-scores { profile-id: new-id, domain: DOMAIN-GENERAL }    { score: u0, last-update: block-height, event-count: u0 })

        (var-set next-profile-id (+ new-id u1))
        (ok new-id)
    )
)

;; Submit a behavioral event for a target profile.
;; Only approved oracles may call this function.
;; delta is a signed integer representing the score change (-1000 to +1000).
(define-public (submit-wave-event (target principal) (domain uint) (delta int))
    (let (
        (caller         tx-sender)
        (profile-id     (unwrap! (map-get? principal-to-id target) ERR-NOT-REGISTERED))
        (current-entry  (unwrap! (map-get? domain-scores { profile-id: profile-id, domain: domain }) ERR-INVALID-DOMAIN))
        (seq            (var-get next-event-seq))
    )
        ;; Only approved oracles
        (asserts! (default-to false (map-get? approved-oracles caller)) ERR-NOT-AUTHORIZED)
        ;; Oracles cannot boost their own profile
        (asserts! (not (is-eq caller target)) ERR-SELF-ATTESTATION)
        (asserts! (valid-domain domain) ERR-INVALID-DOMAIN)

        (let (
            (new-score (adjust-score
                            (get score current-entry)
                            (get last-update current-entry)
                            delta))
        )
            ;; Update domain score
            (map-set domain-scores { profile-id: profile-id, domain: domain } {
                score:          new-score,
                last-update:    block-height,
                event-count:    (+ (get event-count current-entry) u1)
            })

            ;; Persist event to the wave log
            (map-set wave-events seq {
                profile-id:     profile-id,
                domain:         domain,
                delta:          delta,
                submitted-by:   caller,
                block-height:   block-height
            })
            (var-set next-event-seq (+ seq u1))

            (ok new-score)
        )
    )
)

;; ---------------------------------------------------------------
;; Layer 3 - Credibility Oracle: Read-Only Queries
;; ---------------------------------------------------------------

;; Return the live (decay-adjusted) credibility score for a principal in a domain.
;; Returns none if the principal is not registered or the domain is invalid.
(define-read-only (get-credibility-score (target principal) (domain uint))
    (match (map-get? principal-to-id target)
        profile-id
            (match (map-get? domain-scores { profile-id: profile-id, domain: domain })
                entry
                    (some (apply-decay (get score entry) (get last-update entry)))
                none
            )
        none
    )
)

;; Return the raw stored score (before decay) for inspection
(define-read-only (get-raw-domain-entry (target principal) (domain uint))
    (match (map-get? principal-to-id target)
        profile-id (map-get? domain-scores { profile-id: profile-id, domain: domain })
        none
    )
)

;; Return the profile metadata for a principal
(define-read-only (get-profile (target principal))
    (match (map-get? principal-to-id target)
        profile-id (map-get? profiles profile-id)
        none
    )
)

;; Return event details by sequence number
(define-read-only (get-wave-event (seq uint))
    (map-get? wave-events seq)
)

;; Check whether an address is an approved oracle
(define-read-only (is-approved-oracle (oracle principal))
    (default-to false (map-get? approved-oracles oracle))
)

;; ---------------------------------------------------------------
;; Cross-Chain Portability
;; ---------------------------------------------------------------

;; Link a remote chain identity hash to the caller's local profile.
;; cid identifies the external chain; remote-hash is the keccak/sha256
;; hash of the caller's address on that chain, provided off-chain.
(define-public (link-cross-chain-identity (cid uint) (remote-hash (buff 32)))
    (let (
        (profile-id (unwrap! (map-get? principal-to-id tx-sender) ERR-NOT-REGISTERED))
    )
        (map-set cross-chain-links { cid: cid, remote-hash: remote-hash } profile-id)
        (ok true)
    )
)

;; Resolve a remote identity hash to a local profile ID
(define-read-only (resolve-cross-chain (cid uint) (remote-hash (buff 32)))
    (map-get? cross-chain-links { cid: cid, remote-hash: remote-hash })
)

;; ---------------------------------------------------------------
;; Admin: Oracle Management (contract owner only)
;; ---------------------------------------------------------------

(define-public (add-oracle (oracle principal))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (map-set approved-oracles oracle true)
        (ok true)
    )
)

(define-public (remove-oracle (oracle principal))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (map-delete approved-oracles oracle)
        (ok true)
    )
)

;; Deactivate a profile (owner or contract owner)
(define-public (deactivate-profile (target principal))
    (let (
        (profile-id (unwrap! (map-get? principal-to-id target) ERR-NOT-REGISTERED))
        (profile    (unwrap! (map-get? profiles profile-id) ERR-NOT-REGISTERED))
    )
        (asserts!
            (or (is-eq tx-sender CONTRACT-OWNER) (is-eq tx-sender (get owner profile)))
            ERR-NOT-AUTHORIZED)
        (map-set profiles profile-id (merge profile { active: false }))
        (ok true)
    )
)
