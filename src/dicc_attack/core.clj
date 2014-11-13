(ns dicc-attack.core
  (:import [org.mindrot.jbcrypt BCrypt])
  (:require [clojure.java.io :as io]))

(defn- dictionary-attack-text [dictionary check-pass-func encrypted-text]
  "Dictionary attack to an encrypted text"
  (if (clojure.string/blank? encrypted-text) nil
      (with-open [rdr (clojure.java.io/reader dictionary)]
        (if-let [plain-text (some #(if (check-pass-func % encrypted-text) %) (line-seq rdr))]
          (str plain-text "=F(" encrypted-text ")")
          nil))))

(defn- parallel-dictionary-attack-text [dictionary check-pass-func encrypted-text]
  "Parallel version of dictionary-attack-text"
  (if (clojure.string/blank? encrypted-text) nil
      (with-open [rdr (clojure.java.io/reader dictionary)]
        (if-let [plain-text (first (filter #(not (nil? %))
                                           (pmap #(if (check-pass-func % encrypted-text) % nil) (line-seq rdr))))]
          (str plain-text "=F(" encrypted-text ")")
          nil))))

(defn check-bcrypt [plain-text encrypted-text]
  "Checks if encrypted-text = BCrypt(plain-text)"
  (BCrypt/checkpw plain-text encrypted-text))

(defn dictionary-attack
  "Dictionary attack to encrypted-passwords contained in the given file parameter (one per line)"
  [file dictionary check-pass-func]
  (with-open [rdr (clojure.java.io/reader file)]
    (doall (map #(dictionary-attack-text dictionary check-pass-func %) (line-seq rdr)))))

(defn parallel-dictionary-attack
  "Parallel version of crack-from-file"
  [file dictionary check-pass-func]
  (with-open [rdr (clojure.java.io/reader file)]
    (doall (pmap #(parallel-dictionary-attack-text dictionary check-pass-func %) (line-seq rdr)))))
