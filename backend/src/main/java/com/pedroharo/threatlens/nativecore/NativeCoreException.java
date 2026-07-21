package com.pedroharo.threatlens.nativecore;

public class NativeCoreException extends RuntimeException {
    public NativeCoreException(String message) {
        super(message);
    }

    public NativeCoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
