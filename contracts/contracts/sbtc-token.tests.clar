;; Invariants

(define-read-only (invariant-total-supply-eq-locked-plus-unlocked)
  (is-eq
    (unwrap-panic (get-total-supply))
    (+ (ft-get-supply sbtc-token) (ft-get-supply sbtc-token-locked)))
)

(define-read-only (invariant-locked-supply-lt-total-supply)
  (<= (ft-get-supply sbtc-token-locked) (unwrap-panic (get-total-supply)))
)

(define-read-only (invariant-unlocked-supply-lt-total-supply)
  (<= (ft-get-supply sbtc-token) (unwrap-panic (get-total-supply)))
)

(define-read-only (invariant-locked-lt-eq-supply (address principal))
  (<=
    (ft-get-balance sbtc-token-locked address)
    (ft-get-supply sbtc-token-locked)
  )
)

(define-read-only (invariant-unlocked-lt-supply (address principal))
  (<=
    (ft-get-balance sbtc-token address)
    (ft-get-supply sbtc-token)
  )
)

(define-constant initial-token-uri
  (some u"https://ipfs.io/ipfs/bafkreibqnozdui4ntgoh3oo437lvhg7qrsccmbzhgumwwjf2smb3eegyqu")
)

(define-read-only (invariant-token-uri-none)
  (let
    (
      (num-calls-set-token-uri
        (unwrap-panic (get called (map-get? context "protocol-set-token-uri")))
      )
    )
    (if
      (is-eq num-calls-set-token-uri u0)
      (is-eq (var-get token-uri) initial-token-uri)
      true
    )
  )
)

(define-read-only (invariant-supply-0-before-mint)
  (let
    (
      (num-calls-mint
        (unwrap-panic (get called (map-get? context "protocol-mint")))
      )
      (num-calls-mint-many
        (unwrap-panic (get called (map-get? context "protocol-mint-many")))
      )
    )
    (if
      (and (is-eq num-calls-mint u0) (is-eq num-calls-mint-many u0))
      (is-eq (unwrap-panic (get-total-supply)) u0)
      true
    )
  )
)

;; Properties

(define-constant ERR_ASSERTION_FAILED (err u999))
(define-constant REGISTRY_ERR_UNAUTHORIZED (err u400))

(define-constant registry-governance-role 0x00)
(define-constant registry-deposit-role 0x01)
(define-constant registry-withdrawal-role 0x02)

;; Protocol Mint

(define-data-var amount-mint-tmp uint u0)
(define-data-var recipient-mint-tmp principal tx-sender)

(define-public (test-protocol-mint-unauthorized
    (amount uint)
    (recipient principal)
  )
  (begin
    (var-set amount-mint-tmp amount)
    (var-set recipient-mint-tmp recipient)
    (asserts!
      (is-eq
        (map
          test-protocol-mint-unauthorized-inner
          (list
            registry-governance-role
            registry-deposit-role
            registry-withdrawal-role
          )
        )
        (list (ok true) (ok true) (ok true))
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

(define-private (test-protocol-mint-unauthorized-inner
    (contract-flag (buff 1))
  )
  (begin
    (asserts!
      (is-eq
        (protocol-mint
          (var-get amount-mint-tmp)
          (var-get recipient-mint-tmp)
          contract-flag
        )
        REGISTRY_ERR_UNAUTHORIZED
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

;; Protocol Burn

(define-data-var amount-burn-tmp uint u0)
(define-data-var owner-burn-tmp principal tx-sender)

(define-public (test-protocol-burn-unauthorized
    (amount uint)
    (owner principal)
  )
  (begin
    (var-set amount-burn-tmp amount)
    (var-set owner-burn-tmp owner)
    (asserts!
      (is-eq
        (map
          test-protocol-burn-unauthorized-inner
          (list
            registry-governance-role
            registry-deposit-role
            registry-withdrawal-role
          )
        )
        (list (ok true) (ok true) (ok true))
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

(define-private (test-protocol-burn-unauthorized-inner
    (contract-flag (buff 1))
  )
  (begin
    (asserts!
      (is-eq
        (protocol-burn
          (var-get amount-burn-tmp)
          (var-get owner-burn-tmp)
          contract-flag
        )
        REGISTRY_ERR_UNAUTHORIZED
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

;; Protocol Lock
(define-public (test-protocol-lock-unauthorized-governance-role
    (owner principal)
    (amount uint)
  )
  (begin
    (asserts!
      (is-eq
        (protocol-lock amount owner registry-governance-role)
        REGISTRY_ERR_UNAUTHORIZED
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

(define-public (test-protocol-lock-unauthorized-deposit-role
    (owner principal)
    (amount uint)
  )
  (begin
    (asserts!
      (is-eq
        (protocol-lock amount owner registry-deposit-role)
        REGISTRY_ERR_UNAUTHORIZED
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

(define-public (test-protocol-lock-unauthorized-withdrawal-role
    (owner principal)
    (amount uint)
  )
  (begin
    (asserts!
      (is-eq
        (protocol-lock amount owner registry-withdrawal-role)
        REGISTRY_ERR_UNAUTHORIZED
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

;; Protocol Unlock

(define-data-var amount-unlock-tmp uint u0)
(define-data-var owner-unlock-tmp principal tx-sender)

(define-public (test-protocol-unlock-unauthorized
    (amount uint)
    (owner principal)
  )
  (begin
    (var-set amount-unlock-tmp amount)
    (var-set owner-unlock-tmp owner)
    (asserts!
      (is-eq
        (map
          test-protocol-unlock-unauthorized-inner
          (list
            registry-governance-role
            registry-deposit-role
            registry-withdrawal-role
          )
        )
        (list (ok true) (ok true) (ok true))
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

(define-private (test-protocol-unlock-unauthorized-inner
    (contract-flag (buff 1))
  )
  (begin
    (asserts!
      (is-eq
        (protocol-unlock
          (var-get amount-unlock-tmp)
          (var-get owner-unlock-tmp)
          contract-flag
        )
        REGISTRY_ERR_UNAUTHORIZED
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

;; Protocol Burn Locked

(define-data-var amount-burn-locked-tmp uint u0)
(define-data-var owner-burn-locked-tmp principal tx-sender)

(define-public (test-protocol-burn-locked-unauthorized
    (amount uint)
    (owner principal)
  )
  (begin
    (var-set amount-burn-locked-tmp amount)
    (var-set owner-burn-locked-tmp owner)
    (asserts!
      (is-eq
        (map
          test-protocol-burn-locked-unauthorized-inner
          (list
            registry-governance-role
            registry-deposit-role
            registry-withdrawal-role
          )
        )
        (list (ok true) (ok true) (ok true))
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

(define-private (test-protocol-burn-locked-unauthorized-inner
    (contract-flag (buff 1))
  )
  (begin
    (asserts!
      (is-eq
        (protocol-burn-locked
          (var-get amount-burn-locked-tmp)
          (var-get owner-burn-locked-tmp)
          contract-flag
        )
        REGISTRY_ERR_UNAUTHORIZED
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

;; Protocol Set Name

(define-data-var new-name-tmp (string-ascii 32) "")

(define-public (test-protocol-set-name-unauthorized
    (new-name (string-ascii 32))
  )
  (begin
    (var-set new-name-tmp new-name)
    (asserts!
      (is-eq
        (map
          test-protocol-set-name-unauthorized-inner
          (list
            registry-governance-role
            registry-deposit-role
            registry-withdrawal-role
          )
        )
        (list (ok true) (ok true) (ok true))
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

(define-private (test-protocol-set-name-unauthorized-inner
    (contract-flag (buff 1))
  )
  (begin
    (asserts!
      (is-eq
        (protocol-set-name (var-get new-name-tmp) contract-flag)
        REGISTRY_ERR_UNAUTHORIZED
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

;; Protocol Set Token URI

(define-data-var new-uri-tmp (optional (string-utf8 256)) none)

(define-public (test-protocol-set-token-uri-unauthorized
    (new-uri (optional (string-utf8 256)))
  )
  (begin
    (var-set new-uri-tmp new-uri)
    (asserts!
      (is-eq
        (map
          set-token-uri-unauthorized-inner
          (list
            registry-governance-role
            registry-deposit-role
            registry-withdrawal-role
          )
        )
        (list (ok true) (ok true) (ok true))
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

(define-private (set-token-uri-unauthorized-inner (contract-flag (buff 1)))
  (begin
    (asserts!
      (is-eq
        (protocol-set-token-uri (var-get new-uri-tmp) contract-flag)
        REGISTRY_ERR_UNAUTHORIZED
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

;; Protocol Set Symbol

(define-data-var new-symbol-tmp (string-ascii 10) "")

(define-public (test-protocol-set-symbol-unauthorized
    (new-symbol (string-ascii 10))
  )
  (begin
    (var-set new-symbol-tmp new-symbol)
    (asserts!
      (is-eq
        (map
          set-symbol-unauthorized-inner
          (list
            registry-governance-role
            registry-deposit-role
            registry-withdrawal-role
          )
        )
        (list (ok true) (ok true) (ok true))
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

(define-private (set-symbol-unauthorized-inner (contract-flag (buff 1)))
  (begin
    (asserts!
      (is-eq
        (protocol-set-symbol (var-get new-symbol-tmp) contract-flag)
        REGISTRY_ERR_UNAUTHORIZED
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)
