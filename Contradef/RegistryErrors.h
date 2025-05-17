#pragma once
#ifndef REGISTRY_ERRORS_H
#define REGISTRY_ERRORS_H

enum RegistryError {
    SUCCESS = 0,
    FILE_NOT_FOUND = 2,
    ACCESS_DENIED = 5,
    INVALID_HANDLE = 6,
    INVALID_PARAMETER = 87,
    MORE_DATA = 234
};

#endif // REGISTRY_ERRORS_H
