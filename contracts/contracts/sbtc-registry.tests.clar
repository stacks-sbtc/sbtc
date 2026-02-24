;; Invariants

;; During the invariant testing routine, Rendezvous will attept to create state
;; transitions in the target contract by calling public functions with randomly
;; generated arguments. The caller of the public functions and invariants is
;; also randomly selected from the set of principals that are defined in the
;; `Devnet.toml`. During this process, invariants are continuously checked to
;; ensure that the contract's state remains consistent and adheres to the
;; defined rules.
;; 
;; The invariants can be thought of as properties that must always hold true
;; regardless of the target contract's state, the moment in time (blocks), and
;; considering the target contract alone, without any external dependencies.

;; This invariant checks that, at any point in time, whatever operations are
;; performed on the stxc-registry contract alone, the governance role is always
;; held by the sbtc-bootstrap-signers contract.
(define-read-only (invariant-signers-always-governance-role)
  (is-eq
    (unwrap-panic (map-get? active-protocol-contracts governance-role))
    .sbtc-bootstrap-signers
  )
)

;; This invariant checks that the deposit role is always held by the
;; sbtc-deposit contract.
(define-read-only (invariant-deposit-always-deposit-role)
  (is-eq
    (unwrap-panic (map-get? active-protocol-contracts deposit-role))
    .sbtc-deposit
  )
)

;; This invariant checks that the withdrawal role is always held by the
;; sbtc-withdrawal contract.
(define-read-only (invariant-withdrawal-always-withdraw-role)
  (is-eq
    (unwrap-panic (map-get? active-protocol-contracts withdrawal-role))
    .sbtc-withdrawal
  )
)

;; This invariant checks that, for any arbitrary withdrawal request ID, if it
;; is non-zero and lower than or equal to the last withdrawal request ID, it
;; must exist in the withdrawal requests map.
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

;; This invariant checks that, for any arbitrary withdrawal request ID, if it
;; is zero or greater than the last withdrawal request ID, then the request ID
;; must not exist in the withdrawal requests map.
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

;; This invariant checks that the last withdrawal request ID is always equal to
;; the `create-withdrawal-request` function number of calls. Considering that
;; `create-withdrawal-request` cannot be called without involving the principal
;; that holds the withdrawal role, this invariant is only theoretical.
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

;; This invariant checks that the withdrawal status for a given request ID is
;; always `none` if the `complete-withdrawal-*` functions have not been called
;; during the current invariant testing run. Considering that these methods
;; cannot be called without involving the principal that holds the withdrawal
;; role, this invariant is only theoretical.
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

;; This invariant checks that the current signature threshold is unchanged
;; during the invariant testing run, unless the `rotate-keys` function has been
;; called.
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

(define-constant deployer tx-sender)

;; This invariant checks that the current signer principal is unchanged during
;; the invariant testing run, unless the `rotate-keys` function has been called.
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

;; This invariant checks that the current aggregate public key is unchanged
;; during the invariant testing run, unless the `rotate-keys` function has been
;; called.
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

;; During the property testing routine, Rendezvous will extract the pool of all
;; the property tests that are defined in the target contract's attached test
;; file. It will then statefully and randomly execute these tests, asserting
;; on their results.
;; 
;; The properties can be thought of mathematical statements that must always
;; remain valid, regardless of the arbitrary arguments that are passed to the
;; test functions.

(define-constant ERR_ASSERTION_FAILED (err u1001))

;; This property checks that the `create-withdrawal-request` function returns
;; the expected error code regardless of the standard principal sender of the
;; test and the arguments that are passed to it.
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

;; This property checks that the `create-withdrawal-request` function does not
;; update the last withdrawal request ID variable regardless of the standard
;; principal sender of the test and the arguments that are passed to it. The
;; sender that can create a withdrawal request is the one that holds the
;; withdrawal role, which initially is the sbtc-withdrawal contract and cannot
;; be changed during the property testing run.
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

;; This property checks that the `complete-withdrawal-accept` function returns
;; the expected error code regardless of the standard principal sender of the
;; test and the arguments that are passed to it.
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

;; This property checks that the `complete-withdrawal-reject` function returns
;; the expected error code regardless of the standard principal sender of the
;; test and the arguments that are passed to it.
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