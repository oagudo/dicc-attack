# dicc-attack

A Clojure library designed to make dictionary attacks given an encryption function (E)

## Usage

(dictionary-attack "encrypted-pass-file" "dictionary-file" check-pass-func)

or its parallel version

(parallel-dictionary-attack "encrypted-pass-file" "dictionary-file" check-pass-func)

where

    check-pass-func => E(plain-text) == encrypted-text