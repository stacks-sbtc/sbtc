;; Invariants

(define-constant deployer tx-sender)

(define-read-only (invariant-signers-always-governance-role)
  (is-eq
    (unwrap-panic (map-get? active-protocol-contracts governance-role))
    .sbtc-bootstrap-signers
  )
)

(define-read-only (invariant-deposit-always-deposit-role)
  (is-eq
    (unwrap-panic (map-get? active-protocol-contracts deposit-role))
    .sbtc-deposit
  )
)

(define-read-only (invariant-withdrawal-always-withdraw-role)
  (is-eq
    (unwrap-panic (map-get? active-protocol-contracts withdrawal-role))
    .sbtc-withdrawal
  )
)

(define-read-only (invariant-withdraw-req-id-some (id uint))
  (if
    (and
      (<= id (var-get last-withdrawal-request-id))
      (> id u0)
    )
    (is-some (map-get? withdrawal-requests id))
    true
  )
)

(define-read-only (invariant-withdraw-req-id-none (id uint))
  (if
    (or
      (> id (var-get last-withdrawal-request-id))
      (is-eq id u0)
    )
    (is-none (map-get? withdrawal-requests id))
    true
  )
)

(define-read-only (invariant-last-withraw-req-id-eq-num-calls)
  (let
    (
      (num-calls-withdraw-req
        (default-to
          u0
          (get called (map-get? context "create-withdrawal-request"))
        )
      )
    )
    (is-eq (var-get last-withdrawal-request-id) num-calls-withdraw-req)
  )
)

(define-read-only (invariant-withdrawal-status-none (req-id uint))
  (let
    (
      (num-calls-withdraw-accept
        (default-to
          u0
          (get called (map-get? context "complete-withdrawal-accept"))
        )
      )
      (num-calls-withdraw-reject
        (default-to
          u0
          (get called (map-get? context "complete-withdrawal-reject"))
        )
      )
    )
    (if
      (and
        (is-eq num-calls-withdraw-accept u0)
        (is-eq num-calls-withdraw-reject u0)
      )
      (is-none (map-get? withdrawal-status req-id))
      true)
  )
)

(define-read-only (invariant-current-sig-threshold-unchanged)
  (let
    (
      (num-calls-rotate-keys
        (default-to u0 (get called (map-get? context "rotate-keys")))
      )
    )
    (if
      (is-eq num-calls-rotate-keys u0)
      (is-eq (var-get current-signature-threshold) u0)
      true
    )
  )
)

(define-read-only (invariant-current-sig-principal-unchanged)
  (let
    (
      (num-calls-rotate-keys
        (default-to u0 (get called (map-get? context "rotate-keys")))
      )
    )
    (if
      (is-eq num-calls-rotate-keys u0)
      (is-eq (var-get current-signer-principal) deployer)
      true)
  )
)

(define-read-only (invariant-current-agg-pubkey-unchanged)
  (let
    (
      (num-calls-rotate-keys
        (default-to u0 (get called (map-get? context "rotate-keys")))
      )
    )
    (if
      (is-eq num-calls-rotate-keys u0)
      (is-eq (var-get current-aggregate-pubkey) 0x00)
      true
    )
  )
)

;; Properties

(define-constant ERR_WRONG_ERROR_CODE (err u1000))
(define-constant ERR_ASSERTION_FAILED (err u1001))

(define-public (test-standard-principal-sender-withdrawal-unauthorized
    (amount uint)
    (max-fee uint)
    (sender principal)
    (recipient { version: (buff 1), hashbytes: (buff 32) })
    (height uint)
  )
  (begin
    (asserts!
        (is-eq
          (create-withdrawal-request amount max-fee sender recipient height)
          ERR_UNAUTHORIZED
        )
        ERR_ASSERTION_FAILED
      )
    (ok true)
  )
)

(define-public (test-standard-principal-sender-withdrawal-req-id-not-updated
    (amount uint)
    (max-fee uint)
    (sender principal)
    (recipient { version: (buff 1), hashbytes: (buff 32) })
    (height uint)
  )
  (let
    (
      (last-withdrawal-req-id-before (var-get last-withdrawal-request-id))
      (withdrawal-request-result
        (create-withdrawal-request amount max-fee sender recipient height)
      )
    )
    (asserts!
      (is-eq
        (var-get last-withdrawal-request-id)
        last-withdrawal-req-id-before
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

(define-public (test-standard-principal-sender-withdrawal-accept-unauthorized
    (request-id uint)
		(bitcoin-txid (buff 32))
		(output-index uint)
		(signer-bitmap uint)
		(fee uint)
		(burn-hash (buff 32))
		(burn-height uint)
		(sweep-txid (buff 32))
  )
  (begin
    (asserts!
      (is-eq
        (complete-withdrawal-accept
          request-id
          bitcoin-txid
          output-index
          signer-bitmap
          fee
          burn-hash
          burn-height
          sweep-txid
        )
        ERR_UNAUTHORIZED
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)

(define-public (test-standard-principal-sender-withdrawal-reject-unauthorized
    (request-id uint)
    (signer-bitmap uint)
  )
  (begin
    (asserts!
      (is-eq
        (complete-withdrawal-reject request-id signer-bitmap)
        ERR_UNAUTHORIZED
      )
      ERR_ASSERTION_FAILED
    )
    (ok true)
  )
)