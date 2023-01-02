## NAT punch

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

## Arguments for inclusion

It seems likely inevitable that a public directory server would fill up with too registrations,
it might also experience heavy load of forwarded packets. The directory server might need a way
to choose which registrations get cleaned up (and maybe which forward packets get dropped).

One solution might be to introduce an additional parameter to the `Register` packet. Let's call
it the `Argument For Inclusion`, or `arfin`. For example the arfin might encode:
1. Proof of work, "I really want you to include me."
2. Signature by an authorized party. "Public key x says you should inclued me."
3. Others?

Proof of work (1.) is wasteful so perhaps we avoid that one.

Signature by an autorized party (2.) is interesting. For private pkip directory servers on the
public internet an authorization setup falls naturally from the feature. The owner of the
private directory server might use option 2 to authorize all `Register` requests.


Signatures by an authorized party could potentially serve as a monetization strategy for
public directory servers. However, we need to be careful with this approach as greed can
be a risk to protocol design. When a problem can be solved by paying a certain party,
that party may be incentivized to prevent better solutions from being developed.
There is a conflict of interest when a party that benefits from a protocol's flaws has control
over the design or iteration of the protocol. {{Citation needed}}

https://en.wikipedia.org/wiki/Public_key_infrastructure
https://en.wikipedia.org/wiki/Blockchain



