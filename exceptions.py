"""
Custom Exceptions for Password Manager
"""


class VaultException(Exception):
    """Base exception for vault operations"""
    pass


class VaultNotLoadedError(VaultException):
    """Raised when attempting operations on unloaded vault"""
    pass


class VaultCorruptedError(VaultException):
    """Raised when vault file is corrupted or tampered with"""
    pass


class InvalidMasterPasswordError(VaultException):
    """Raised when master password verification fails"""
    pass


class InvalidEntryError(VaultException):
    """Raised when entry data is invalid"""
    pass


class WeakPasswordError(VaultException):
    """Raised when password does not meet strength requirements"""
    pass


class EncryptionError(VaultException):
    """Raised when encryption/decryption fails"""
    pass


class PermissionError(VaultException):
    """Raised when file permissions are incorrect"""
    pass


class BruteForceDetectedError(VaultException):
    """Raised when too many failed unlock attempts detected"""
    pass


class VaultLockedError(VaultException):
    """Raised when vault is locked due to failed attempts"""
    pass


class AuditLoggingError(VaultException):
    """Raised when audit logging fails"""
    pass

