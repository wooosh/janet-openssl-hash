(import openssl-hash)

(def test-vectors [
    # hello world test vectors
    {:alg "SHA256"
     :in  "hello world"
     :out "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"}
    {:alg "MD5"
     :in "hello world"
     :out "5eb63bbbe01eeed093cb22bb8f5acdc3"}
    # empty string test vectors
    {:alg "SHA256"
     :in  ""
     :out "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
    {:alg "MD5"
     :in  ""
     :out "d41d8cd98f00b204e9800998ecf8427e"}
    # containing null bytes
    {:alg "SHA256"
     :in  "hello\x00world"
     :out "b206899bc103669c8e7b36de29d73f95b46795b508aa87d612b2ce84bfb29df2"}
    {:alg "MD5"
     :in  "hello\x00world"
     :out "838d3870873a75639041ff8940f397db"}])

(defn hex-to-raw
    "Convert from a hexadecimal string to the equivalent raw binary string"
    [hex]
    (as-> (string/bytes hex) _
        (if (even? (length _)) _ (string "0" _))
        (seq [digit :in _]
            (cond (<= (chr "0") digit (chr "9")) (- digit (chr "0"))
                  (<= (chr "A") digit (chr "F")) (+ 0xA (- digit (chr "A")))
                  (<= (chr "a") digit (chr "f")) (+ 0xA (- digit (chr "a")))
                  (error "hex string contains invalid characters")))
        (partition 2 _)
        (seq [[hi lo] :in _]
            (+ (blshift hi 4) lo))
        (string/from-bytes ;_)))

(defn assert-hash
    ""
    [hasher expected &opt flag]
    (def result (as-> (openssl-hash/finalize hasher flag) _
                    (if (= flag :hex) (string/ascii-lower _) _)))
    (def expected (as-> (string/ascii-lower expected) _
                    (if (= flag :hex) expected (hex-to-raw expected))))
    (assert (= expected result)))

(defmacro assert-error
    [expr expected-err]
    ~(try
        (do ,expr
            (assert false))
        ([$err] (assert (= $err ,expected-err)))))

#
# test cases
#

(defn simple-hash
    "Test the most basic usage of the hash function, by hashing a single value"
    [vec]
    (each flag [nil :hex]
        (def h (openssl-hash/new (vec :alg)))
        (openssl-hash/feed h (vec :in))
        (assert-hash h (vec :out) flag)))

(defn feed-single-byte
    "Test the hash function by feeding it one byte at a time"
    [vec]
    (each flag [nil :hex]
        (def h (openssl-hash/new (vec :alg)))
        (each c (vec :in)
            (openssl-hash/feed h (string/from-bytes c)))
        (assert-hash h (vec :out) flag)))

(each vec test-vectors
    (simple-hash vec))

# test errors
(assert-error (openssl-hash/new "SHA\x00256")
            "algorithm name invalid due to presence of null characters")

(assert-error (openssl-hash/new "non-existent hash function")
            "no digest algorithm with name 'non-existent hash function'")

(let [h (openssl-hash/new "SHA256")]
    (openssl-hash/finalize h)
    (assert-error (openssl-hash/finalize h) "hash already finalized")
    (assert-error (openssl-hash/feed h "123") "hash already finalized"))

(let [h (openssl-hash/new "SHA256")]
    (assert-error (openssl-hash/finalize h :invalid-flag) "unknown flag :invalid-flag"))

(let [h (openssl-hash/new "SHA256")]
    (assert-error (openssl-hash/feed h 123) "cannot read bytes of data argument"))