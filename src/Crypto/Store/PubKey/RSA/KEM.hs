-- |
-- Module      : Crypto.Store.PubKey.RSA.KEM
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- RSA as a Key-Encapsulation Mechanism (KEM).
module Crypto.Store.PubKey.RSA.KEM
    ( KDF(..), kdf3
    -- * Operations
    , encapsulate, encapsulateWith, decapsulate
    ) where

import           Data.ByteArray (ByteArray, ByteArrayAccess, Bytes)
import qualified Data.ByteArray as B
import           Data.ByteString (ByteString, empty)

import           Crypto.Hash
import           Crypto.Number.Generate
import           Crypto.Number.Serialize (os2ip, i2ospOf_)
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.PubKey.RSA.Types as RSA
import           Crypto.Random

-- | Key derivation used by RSA-KEM.
newtype KDF bIn bOut = KDF (ByteString -> bIn -> bOut)

-- | KDF3 from ANSI X9.44-2007 (R2017)
kdf3 :: (HashAlgorithm a, ByteArrayAccess bIn, ByteArray bOut)
     => a -> Int -> KDF bIn bOut
kdf3 hashAlg outLen = KDF (doKDF3 hashAlg outLen)

doKDF3 :: (HashAlgorithm a, ByteArrayAccess bIn, ByteArray bOut)
       => a -> Int -> ByteString -> bIn -> bOut
doKDF3 hashAlg outLen otherInfo input
    | r == 0    = B.concat $ map doChunk [ 1 .. k ]
    | otherwise = B.take outLen $ B.concat $ map doChunk [ 1 .. k + 1 ]
  where
    (k, r) = outLen `divMod` blk
    blk    = hashDigestSize hashAlg
    doChunk i =
        let ctx0 = hashInitWith hashAlg
            ctx1 = hashUpdate ctx0 (i2ospOf_ 4 (toInteger i) :: Bytes)
            ctx2 = hashUpdate ctx1 input
            ctx3 = hashUpdate ctx2 otherInfo
         in hashFinalize ctx3

-- | Generate a shared secret key and an associated ciphertext using randomness.
encapsulate :: (MonadRandom m, ByteArray ciphertext)
            => KDF ciphertext sharedSecret
            -> RSA.PublicKey
            -> m (sharedSecret, ciphertext)
encapsulate kdf pub = encap kdf pub <$> generateMax (RSA.public_n pub)

-- | Generate a shared secret key and an associated ciphertext using a
-- specified random input.  This input must be an integer in range [0, n) and
-- not repeated with other encapsulations.  For testing purposes.
encapsulateWith :: ByteArray ciphertext
                => KDF ciphertext sharedSecret
                -> RSA.PublicKey
                -> Integer
                -> Maybe (sharedSecret, ciphertext)
encapsulateWith kdf pub z
    | z < 0 || z >= RSA.public_n pub = Nothing
    | otherwise = Just $ encap kdf pub z

encap :: ByteArray ciphertext
      => KDF ciphertext sharedSecret
      -> RSA.PublicKey
      -> Integer
      -> (sharedSecret, ciphertext)
encap (KDF kdf) pub z = (ss, ct)
  where
    zz  = i2ospOf_ (RSA.public_size pub) z
    ct  = RSA.ep pub zz
    ss  = kdf empty zz

-- | Return the shared secret for a given ciphertext.
decapsulate :: ByteArray ciphertext
            => KDF ciphertext sharedSecret
            -> RSA.PrivateKey
            -> ciphertext
            -> Maybe sharedSecret
decapsulate (KDF kdf) priv ct
    | B.length ct < RSA.public_size pub = Nothing
    | c >= RSA.public_n pub = Nothing
    | otherwise = Just ss
  where
    pub = RSA.private_pub priv
    c   = os2ip ct
    zz  = RSA.dp Nothing priv ct
    ss  = kdf empty zz
