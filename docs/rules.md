## Logging
Logging should be conformed within every function meaning, returned values from
a specific function cannot be logged out on another function where the said
function is referenced, an example for an incorrect and correct logging practice:

```
foo() {

    // ...

    log("This is correct logging);

    x = bar();
    log("This is incorrect logging {x}");
}

bar() {
    
    // ...

    log("This is correct logging {x}");
    return x
}
```