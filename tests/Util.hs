{-# LANGUAGE ScopedTypeVariables #-}
-- | Test utilities.
module Util
    ( assertJust
    , assertLeft
    , assertRight
    , getAttached
    , getDetached
    , testFile
    , TestKey(..)
    , TestIV, unIV
    ) where

import Control.Monad (when)

import Data.ByteString (ByteString, pack)
import Data.Maybe (fromJust, isNothing)

import Crypto.Cipher.Types
import Crypto.Store.CMS

import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

assertJust :: Maybe a -> (a -> Assertion) -> Assertion
assertJust (Just a) f = f a
assertJust Nothing  _ = assertFailure "expecting Just but got Nothing"

assertLeft :: Show b => Either a b -> (a -> Assertion) -> Assertion
assertLeft (Left a)  f = f a
assertLeft (Right val) _ =
    assertFailure ("expecting Left but got: Right " ++ show val)

assertRight :: Show a => Either a b -> (b -> Assertion) -> Assertion
assertRight (Right b)  f = f b
assertRight (Left val) _ =
    assertFailure ("expecting Right but got: Left " ++ show val)

getAttached :: Encapsulates struct => struct (Encap a) -> IO (struct a)
getAttached e = do
    let m = fromAttached e
    when (isNothing m) $
        assertFailure "expecting attached but got detached content"
    return $! fromJust m

getDetached :: Encapsulates struct => a -> struct (Encap a) -> IO (struct a)
getDetached c e = do
    let m = fromDetached c e
    when (isNothing m) $
        assertFailure "expecting detached but got attached content"
    return $! fromJust m

testFile :: String -> FilePath
testFile name = "tests/files/" ++ name

newtype TestKey cipher = Key ByteString deriving (Show, Eq)

instance Cipher cipher => Arbitrary (TestKey cipher) where
    arbitrary = Key . pack <$>
        case cipherKeySize cipher of
            KeySizeFixed len -> vector len
            KeySizeRange a b -> choose (a, b) >>= vector
            KeySizeEnum list -> elements list >>= vector
      where cipher = undefined :: cipher

newtype TestIV cipher = IV ByteString deriving (Show, Eq)

unIV :: BlockCipher cipher => TestIV cipher -> IV cipher
unIV (IV ivBS) = fromJust $ makeIV ivBS

instance BlockCipher cipher => Arbitrary (TestIV cipher) where
    arbitrary = IV . pack <$> vector (blockSize cipher)
      where cipher = undefined :: cipher
