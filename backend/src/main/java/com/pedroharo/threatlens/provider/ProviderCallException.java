package com.pedroharo.threatlens.provider;

public class ProviderCallException extends RuntimeException {
    public ProviderCallException(String message) {
        super(message);
    }

    public ProviderCallException(String message, Throwable cause) {
        super(message, cause);
    }
}
