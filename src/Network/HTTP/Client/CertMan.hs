{-# LANGUAGE OverloadedStrings #-}

{- |
Module:      Network.HTTP.Client.CertMan
Description: https with a certificate store
Copyright:   2017 Random J Farmer
License:     MIT

Thank you, Stackoverflow!
http://stackoverflow.com/a/41816183/5808912
-}

module Network.HTTP.Client.CertMan
    ( getURL
    , managerSettings
    , certificateStore
    , newCertificateStoreManager
    , setGlobalManagerFromPath
    , setGlobalManagerFromEnv
    , InvalidCertificateStore(..)
    ) where

import           Control.Exception          (Exception (..), throw, throwIO)
import qualified Data.ByteString            as B
import           Data.ByteString.Lazy       (ByteString)
import qualified Data.ByteString.Lazy       as LB
import           Data.Default.Class         (def)
import           Data.String                (IsString, fromString)
import           Data.Typeable              (Typeable (..))
import           Data.X509.CertificateStore (CertificateStore,
                                             readCertificateStore)
import           Network.Connection         (TLSSettings (TLSSettings))
import           Network.HTTP.Client        (Manager, ManagerSettings,
                                             defaultManagerSettings, httpLbs,
                                             newManager, parseUrlThrow,
                                             responseBody, responseStatus,
                                             responseTimeout,
                                             responseTimeoutMicro,
                                             responseTimeoutNone)
import           Network.HTTP.Client.TLS    (getGlobalManager,
                                             mkManagerSettings, newTlsManager,
                                             setGlobalManager)
import           Network.HTTP.Types         (statusCode)
import           Network.TLS                as TLS
import           Network.TLS.Extra.Cipher   as TLS
import           System.Environment         (lookupEnv)

-- | Create ManagerSettings for a CertificateStore
managerSettings :: CertificateStore -> ManagerSettings
managerSettings store =
  mkManagerSettings settings Nothing
  where settings = TLSSettings params
        params = (TLS.defaultParamsClient "" B.empty) {
          TLS.clientUseServerNameIndication = True
          , TLS.clientShared = def {
              TLS.sharedCAStore = store
              }
          , TLS.clientSupported = def {
              TLS.supportedCiphers = TLS.ciphersuite_default
              }
          }

-- | Read a CertificateStore - a directory with pems inside
certificateStore :: FilePath -> IO CertificateStore
certificateStore ca = do
  mstore <- readCertificateStore ca
  case mstore of
    Just store -> return store
    Nothing    -> throwIO (InvalidCertificateStore ca)

newtype InvalidCertificateStore = InvalidCertificateStore FilePath
  deriving (Show, Typeable, Eq)
instance Exception InvalidCertificateStore

-- | Create a manager using a CA Store
newCertificateStoreManager :: FilePath -> IO Manager
newCertificateStoreManager ca = do
  store <- certificateStore ca
  newManager $ managerSettings store

-- | Set the global manager from a CA Store path.
--
-- Uses the default manager if no filepath
setGlobalManagerFromPath :: Maybe FilePath -> IO ()
setGlobalManagerFromPath ca =
  maybe newTlsManager newCertificateStoreManager ca >>=
    setGlobalManager

-- | Set a global manager from environment variable
--
-- If the environment variable does not exist,
-- a default manager without cert store will be used.
setGlobalManagerFromEnv :: String -> IO ()
setGlobalManagerFromEnv name =
  lookupEnv name >>= setGlobalManagerFromPath

-- | Get the given URL
getURL :: String -> IO ByteString
getURL url = do
  manager <- getGlobalManager
  request <- parseUrlThrow url
  responseBody <$> httpLbs request manager
