(ns dicc-attack.core-test
  (:require [clojure.test :refer :all]
            [dicc-attack.core :refer :all])
  (:import [org.mindrot.jbcrypt BCrypt]))


(defn generate-encrypted-passwords-file [number-pass to-file]
  (with-open [wrtr (clojure.java.io/writer to-file)]
    (dorun (map #(.write wrtr (str (BCrypt/hashpw (str "pass" %) (BCrypt/gensalt 10)) "\n")) (range number-pass)))))

(defn generate-plain-passwords-file [number-pass to-file]
  (with-open [wrtr (clojure.java.io/writer to-file)]
    (dorun (map #(.write wrtr (str "pass" % "\n")) (range number-pass)))))

(defn clean-dictionary-test []
  (do
    (when (.exists (clojure.java.io/file "p.txt")) (clojure.java.io/delete-file "p.txt"))
    (when (.exists (clojure.java.io/file "e.txt")) (clojure.java.io/delete-file "e.txt"))))

(defn prepare-dictionary-test []
  (do
    (clean-dictionary-test)
    (generate-plain-passwords-file 2 "p.txt")
    (generate-encrypted-passwords-file 2 "e.txt")))

(deftest test-check-bcrypt
  (testing "check-bcrypt works as expected"
    (is (= (#(check-bcrypt %1 %2) "pass" (BCrypt/hashpw "pass" (BCrypt/gensalt 10))) true))
    (is (= (#(check-bcrypt %1 %2) "wrong-pass" (BCrypt/hashpw "pass" (BCrypt/gensalt 10))) false))))

(deftest test-dictionary-attack
  (testing "dictionary attack discover encrypted-passwords"
    (do
      (prepare-dictionary-test)
      (is (= (not-any? nil? (dictionary-attack "e.txt" "p.txt" check-bcrypt)) true))
      (clean-dictionary-test))))

(deftest test-parallel-dictionary-attack
  (testing "parallel dictionary attack discover encrypted-passwords"
    (do
      (prepare-dictionary-test)
      (is (= (not-any? nil? (parallel-dictionary-attack "e.txt" "p.txt" check-bcrypt)) true))
      (clean-dictionary-test))))
