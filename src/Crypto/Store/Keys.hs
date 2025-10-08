-- |
-- Module      : Crypto.Store.Keys
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
--
{-# LANGUAGE RecordWildCards #-}
module Crypto.Store.Keys
    ( KeyPair(..), keyPairFromPrivKey, keyPairToPrivKey, keyPairToPubKey
    , keyPairMatchesKey, keyPairMatchesCert
    ) where

import Data.Function (on)
import Data.Maybe (fromMaybe)

import qualified Data.X509 as X509
import Data.X509.EC

import qualified Crypto.PubKey.RSA.Types as RSA
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.Curve448 as X448
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448

import Crypto.Store.PKCS8.EC

-- | Holds a private and public key together, with guaranty that they both
-- match.  Therefore no constructor is exposed.  Content may be accessed
-- through functions 'keyPairToPrivKey' and 'keyPairToPubKey'.
--
-- Call function 'keyPairFromPrivKey' to build a @KeyPair@.
data KeyPair =
      KeyPairRSA RSA.PrivateKey RSA.PublicKey             -- ^ RSA key pair
    | KeyPairDSA DSA.KeyPair                              -- ^ DSA key pair
    | KeyPairEC X509.PrivKeyEC X509.PubKeyEC              -- ^ EC key pair
    | KeyPairX25519 X25519.SecretKey X25519.PublicKey     -- ^ X25519 key pair
    | KeyPairX448 X448.SecretKey X448.PublicKey           -- ^ X448 key pair
    | KeyPairEd25519 Ed25519.SecretKey Ed25519.PublicKey  -- ^ Ed25519 key pair
    | KeyPairEd448 Ed448.SecretKey Ed448.PublicKey        -- ^ Ed448 key pair

instance Show KeyPair where
    showsPrec d keyPair = showParen (d > 10) $
        showString "keyPairFromPrivKey " . showsPrec 11 (keyPairToPrivKey keyPair)

instance Eq KeyPair where
    (==) = (==) `on` keyPairToPrivKey

-- | Builds a key pair from an X.509 private key.
keyPairFromPrivKey :: X509.PrivKey -> KeyPair
keyPairFromPrivKey (X509.PrivKeyRSA priv) = KeyPairRSA priv (RSA.toPublicKey (RSA.KeyPair priv))
keyPairFromPrivKey (X509.PrivKeyDSA priv) = KeyPairDSA (dsaPairFromPriv priv)
keyPairFromPrivKey (X509.PrivKeyEC priv) = KeyPairEC priv (ecPubFromPriv priv)
keyPairFromPrivKey (X509.PrivKeyX25519 priv) = KeyPairX25519 priv (X25519.toPublic priv)
keyPairFromPrivKey (X509.PrivKeyX448 priv) = KeyPairX448 priv (X448.toPublic priv)
keyPairFromPrivKey (X509.PrivKeyEd25519 priv) = KeyPairEd25519 priv (Ed25519.toPublic priv)
keyPairFromPrivKey (X509.PrivKeyEd448 priv) = KeyPairEd448 priv (Ed448.toPublic priv)

dsaPairFromPriv :: DSA.PrivateKey -> DSA.KeyPair
dsaPairFromPriv k = DSA.KeyPair params y x
  where y       = DSA.calculatePublic params x
        params  = DSA.private_params k
        x       = DSA.private_x k

ecPubFromPriv :: X509.PrivKeyEC -> X509.PubKeyEC
ecPubFromPriv priv = case priv of
    X509.PrivKeyEC_Prime{..} -> X509.PubKeyEC_Prime
        { pubkeyEC_pub = getSerializedPoint curve privkeyEC_priv
        , pubkeyEC_a = privkeyEC_a
        , pubkeyEC_b = privkeyEC_b
        , pubkeyEC_prime = privkeyEC_prime
        , pubkeyEC_generator = privkeyEC_generator
        , pubkeyEC_order = privkeyEC_order
        , pubkeyEC_cofactor = privkeyEC_cofactor
        , pubkeyEC_seed = privkeyEC_seed
        }
    X509.PrivKeyEC_Named{..} -> X509.PubKeyEC_Named
        { X509.pubkeyEC_name = privkeyEC_name
        , X509.pubkeyEC_pub = getSerializedPoint curve privkeyEC_priv
        }
  where curve = fromMaybe (error "ecPubFromPriv: invalid EC parameters") (ecPrivKeyCurve priv)

-- | Gets the X.509 private key in a key pair.
keyPairToPrivKey :: KeyPair -> X509.PrivKey
keyPairToPrivKey (KeyPairRSA priv _) = X509.PrivKeyRSA priv
keyPairToPrivKey (KeyPairDSA pair) = X509.PrivKeyDSA (DSA.toPrivateKey pair)
keyPairToPrivKey (KeyPairEC priv _) = X509.PrivKeyEC priv
keyPairToPrivKey (KeyPairX25519 priv _) = X509.PrivKeyX25519 priv
keyPairToPrivKey (KeyPairX448 priv _) = X509.PrivKeyX448 priv
keyPairToPrivKey (KeyPairEd25519 priv _) = X509.PrivKeyEd25519 priv
keyPairToPrivKey (KeyPairEd448 priv _) = X509.PrivKeyEd448 priv

-- | Gets the X.509 public key in a key pair.
keyPairToPubKey :: KeyPair -> X509.PubKey
keyPairToPubKey (KeyPairRSA _ pub) = X509.PubKeyRSA pub
keyPairToPubKey (KeyPairDSA pair) = X509.PubKeyDSA (DSA.toPublicKey pair)
keyPairToPubKey (KeyPairEC _ pub) = X509.PubKeyEC pub
keyPairToPubKey (KeyPairX25519 _ pub) = X509.PubKeyX25519 pub
keyPairToPubKey (KeyPairX448 _ pub) = X509.PubKeyX448 pub
keyPairToPubKey (KeyPairEd25519 _ pub) = X509.PubKeyEd25519 pub
keyPairToPubKey (KeyPairEd448 _ pub) = X509.PubKeyEd448 pub

-- | Returns 'True' when the given X.509 public key is consistent with a key
-- pair, which means that the public key can be derived from the private key in
-- the key pair.
keyPairMatchesKey :: KeyPair -> X509.PubKey -> Bool
keyPairMatchesKey (KeyPairRSA _ pub) (X509.PubKeyRSA other) = pub == other
keyPairMatchesKey (KeyPairDSA pair) (X509.PubKeyDSA other) = DSA.toPublicKey pair == other
keyPairMatchesKey (KeyPairEC _ pub) (X509.PubKeyEC other) = pub == other
keyPairMatchesKey (KeyPairX25519 _ pub) (X509.PubKeyX25519 other) = pub == other
keyPairMatchesKey (KeyPairX448 _ pub) (X509.PubKeyX448 other) = pub == other
keyPairMatchesKey (KeyPairEd25519 _ pub) (X509.PubKeyEd25519 other) = pub == other
keyPairMatchesKey (KeyPairEd448 _ pub) (X509.PubKeyEd448 other) = pub == other
keyPairMatchesKey _ _ = False

keyPairMatchesCert :: KeyPair -> X509.SignedCertificate -> Bool
keyPairMatchesCert keyPair cert =
    let obj = X509.signedObject (X509.getSigned cert)
        pub = X509.certPubKey obj
     in keyPairMatchesKey keyPair pub
