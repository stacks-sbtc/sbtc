;; Properties

(define-constant ERR_ASSERTION_FAILED (err u1001))
(define-constant ERR_UNWRAP_FAILURE (err u1002))

(define-constant registry-withdrawal-role 0x02)

;; This is a test utility, not an assertion. It randomly mints sbtc-tokens to
;; users, supporting other tests. During the property testing routine, it will
;; be eventually picked up by rendezous and executed, resulting in a random
;; mint of sbtc-tokens to a random user.
(define-public (test-mint (amount uint) (recipient principal))
  (if
    (is-eq amount u0)
    (ok false)
    (contract-call?
      .sbtc-token
      protocol-mint
      amount
      recipient
      registry-withdrawal-role
    )
  )
)

(define-public (test-initiate-withdrawal-locked-balance
    (amount uint)
    (recipient { version: (buff 1), hashbytes: (buff 32) })
    (max-fee uint)
  )
  (if
    (or
      (<= amount DUST_LIMIT)
      (<
        (unwrap-panic
          (contract-call? .sbtc-token get-balance-available tx-sender)
        )
        (+ amount max-fee)
      )
      (is-err (validate-recipient recipient))
    )
    (ok false)
    (let
      (
        (balance-locked-before
          (unwrap-panic
            (contract-call? .sbtc-token get-balance-locked tx-sender)
          )
        )
      )
      (try! (initiate-withdrawal-request amount recipient max-fee))
      (asserts!
        (is-eq
          (unwrap-panic
            (contract-call? .sbtc-token get-balance-locked tx-sender)
          )
          (+ balance-locked-before amount max-fee)
        )
        ERR_ASSERTION_FAILED
      )
      (ok true)
    )
  )
)

(define-public (test-initiate-withdrawal-available-balance
    (amount uint)
    (recipient { version: (buff 1), hashbytes: (buff 32) })
    (max-fee uint)
  )
  (if
    (or
      (<= amount DUST_LIMIT)
      (<
        (unwrap-panic
          (contract-call? .sbtc-token get-balance-available tx-sender)
        )
        (+ amount max-fee)
      )
      (is-err (validate-recipient recipient))
    )
    (ok false)
    (let
      (
        (balance-available-before
          (unwrap-panic
            (contract-call? .sbtc-token get-balance-available tx-sender)
          )
        )
      )
      (try! (initiate-withdrawal-request amount recipient max-fee))
      (asserts!
       (is-eq
          (unwrap-panic
            (contract-call? .sbtc-token get-balance-available tx-sender)
          )
          (- balance-available-before amount max-fee)
        )
        ERR_ASSERTION_FAILED
      )
      (ok true)
    )
  )
)

(define-public (test-initiate-withdrawal-dust-amount
    (amount uint)
    (recipient { version: (buff 1), hashbytes: (buff 32) })
    (max-fee uint)
  )
  (if
    (or
      (is-eq amount u0)
      (> amount DUST_LIMIT)
      (<
        (unwrap-panic
          (contract-call? .sbtc-token get-balance-available tx-sender)
        )
        (+ amount max-fee)
      )
    )
    (ok false)
    (begin
      (asserts!
        (is-eq
          (initiate-withdrawal-request amount recipient max-fee)
          ERR_DUST_LIMIT
        )
        ERR_ASSERTION_FAILED
      )
      (ok true)
    )
  )
)