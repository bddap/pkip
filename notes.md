## Nat punch

consider an "Introduce Us" packet sent from the application client to the directory server

```
appclient                   directory server                      appserver
   |      --introduce us-->       |                                   |
   |                              |          --register client-->     |
   |      <----------------------------------------------hello------  |
```

Maybe this can be built atop on the "relay" functionality. Maybe the directory server doesn't
need to know about "introductions".

## Reliable registration

how do we check whether registration was successful?
- Send a Forward packet to self with a random payload?
- Make a Lookup query?
