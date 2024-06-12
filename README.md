# Identity Plus mTLS Persona
An mTLS ID Facade for non-mTLS capable (TCP) applications


## Introduction
mTLS Persona is a small tool that transforms a non TLS communication into a TLS communication. The principle of operation is relatively simple, it operates as a TCP forwarder, such that the inboud traffic is a plain-text TCP communciation, and the outbound traffic is standard TLS encrypted TCP communication. In particular, mTLS persona is a utility applciation specific to the Identity Plus ecosystem to help enable mutually authenticated TLS between any two client / service applications use-cases, whether there is native TLS support in the peer application or not. As such, mTLS Persona is works by wrapping communication into a mutually authenticated TLS communication channel, instead of a simple TLS channel, therefore it operates using a client certificate / private key pair, to authenticate itself to the receiving end of the TLS communication, and, it is validating the server TLS certiciate against a trust chain. 

#### Not a Forward Proxy
mTLS Persona is not a complete forward proxy solution, in the sense that it does not allow the client end of the communication to control the destination end, rather, it forces the client through a predefined channel which is pre-defined in the configuration panel. This, however, is specific feature, not a bug, designed to circumvent the need for any sort of "buy in" from the client application. Forwards proxies, such as SOCKS require the client to be aware of the SOCKS protocol and decorate the TCP/TLS communication with additional information which tells the SOCKS proxy where to open the outbound coonection to. This however represents a limitation in certain implementations because not all applications support such protocol, and if they do, code changes or at least configuration changes must be enforced, which sometimes is difficult. mTLS Persona on the other hand, completely fools the client to believing that it in fact communicates with a local service over plain text TCP, whereas in fact, the communication is not only secured, but also authenticated, once it leaves the local premises of the client. In this sens, from an Identity Plus identity principles perspective, it shall be considered that mTLS Persona is part of the "perimeter of one" of the client, as in, it is part of the client from a topology and logical perspective, as the mTLS Persona component gives identity to the underlying, non-cooperating, client application.

#### Performance
mTLS Persona is designed with high performance in mind. It is a highly threaded application, working event based. It only opens connection to remote destinations if it receives an inbound request and it is aware to close corresponding  connections if one of the peers closes their connection. As such, it will not keep alive, unnecessarily, TCP connections to services. It is normal to expect that mTLS Persona will increase the latency of the connection, as it transforms a non-TLS connection into a mutual-TLS connection which, as a protocol, requires additional roundtrips between peers. Once the connection has been established however, no additional latency should be obsereved, as the upstream connection is kept open as long as peers consider it necessary. During packet transmission there may be additional compute resources necessary to encrypt the communication. On machines where symmetric encryption is hardware accelerated, this will not impact the rest of the compute. Generally speaking, the impact of encryption is tiny, and should not be noticeable unless we are talking about extremely low powered systems or extremely low margins for compute induced latency, nanoseconds.  

#### Why is mTLS Persona Needed
Briefly put, because the vast majority of applications today operate on de-facto identity model based on local user names and passwords (or some variations which we call the credential paradigm). This model not only rigid, but also highly insecure, a "deadly" combination because inability to change (rigidity) generates security gaps. Identity Plus brings a completely new model where security and flexibility work in tandem, but it requires the service to implement a novel authentication model. For the services that are impossible to adapt to such requirement (legacy code, legacy placement, lack of access, etc.) we can enforce the new identity/authentication model using an Identity Plus aware reverse proxy (like Instant mTLS).

Generally speaking, applications that implement TLS at the full extent of the standard and not exceeding the standard do not require mTLS Persona. If the client application conforms to vanilla mTLS, it is generally configurable to (using enviornment variables) to operate with the three elements required on the client side for mTLS: client-certificate, corresponding private key and certificate authority trust store. This is the case for the vast majoity of applications that are designed to work over HTTP standard in the application layer. The reason for this is that on the service end, HTTP based applications are designed to work behind a load balancer, which generally offloads the TLS and enforces the vanilla standard and Identity Plus soliution is generally a drop-in or add-on. In case of non-HTTP based applications the problem is a bit more nuanced:

If the client and the service is implement TLS in a non vanilla manner, meaning it requires both of them to be aware of the particularities of the protocol, it is not possible to place a TCP load-balancer/reverse proxy, because it will revert the expected protocol to standard TLS which may not be sufficient. This can be overcome with mTLS Persona, as we can make the client and the service believe they are operating via non-TLS (plain text) but in fact, we route the traffic inside an mTLS envelope.

## Operating Principle
High level, mTLS Persona routes the traffic between two endpoints, a local endpoint and a remote endpoint, where the remote end point is expecting Identity Plus mTLS authentication, by wrapping the local traffic inside an mTLS connection which it opens using an mTLS ID from Identity Plus.

As such, it basically fools a non-cooperating client into believing it communicates plain-text with a local server and fools a non cooperating service (worst case scenario) into believing it is taling with a local client, the IP of which is in fact reverse proxy offloading the mTLS connection. See schematics. 

                         
                          mTLS Persona                       mTLS Gateway
      TCP Client       \--------------------          --------------------/
    ----------------->   local:port -------     ...    ------ remote:port  --------------> TCP Service
                       /--------------------          --------------------\

This happens by configuring the client (for ex: PgAdmin or PostgreSQL Admin) to open a connection to the local inbound poirt (localhost:5432) - PostgreSQL is a good example, as the client and the service use an extended TLS protocol. However, instead of the PostgreSQL server, localhost:5432 is in fact bound by Identity Plus mTLS Persona. When connection request is received, mTLS Persona will open an mTLS connection to remote:5432 using an Identity Plus mTLS ID, where an Identity Plus aware reverse proxy sits (Instant mTLS being a good example). The reverse proxy needs to be able to perform TLS over TCP load balancing - the majority are - as this is a non-HTTP communication. The reverse proxy offloads the TLS and performs the Identity Plus identity and role validations and, in case it decides the connection can be allowed through, it will forward the offloaded (plain-text) connection to a local.network:5432 address, where the PostgreSQL service sits and expects connections.

Although pgAdmin and PostgreSQL server believe they are communicating in plain text, we have in fact layerd upon, without the cooperation of the services, the Indentity Plus access control and the security layer of mTLS.

## How to Use

mTLS Persona is designed to work with Identity Plus mTLS IDs. As mTLS IDs are client certificates and they expire, mTLS Persona will have to work in conjunction with the Identity Plus CLI (Command Line Interface), which ensures rotation of the certificate when necessary. mTLS ID is designed to pick up the certicate dynamically if it has been rotated therefore, no service interruptions will occur. 

The mTLS Identity inforamiton is loaded from a configuration directory which sits usually sits in /etc/something, but it is configurable in the config.json file:

    "client_cert": "/etc/something/agent-name.certificate.pem",
    "client_key": "/etc/something/agent-name.privatekey.pem",
    "ca_cert": "/etc/local-postgres/identity-plus-node-ca-certificate-trust-store.pem",

The time of the validation of the certificate change is specified by the reload hour config parameter. mTLS IDs are rotated at 3/4 of their lifetime, which is generally in order of months, a daily verification is well within the margin of error to prevent accidental expiration. You can however configure this reload time and the cli cron job such that the interval between them is hours or minutes. 

    reload_hour:3  // meaning 3AM, in a millitary (0 - 23) hours based system

The only additional parameter to configure is the port mappings:

        {
            "inbound": "localhost:5432",
            "outbound": "remote.domain.com:5432" // IP address can be used instead of domains
        }

While it works with fixed destination, mTLS Persona allows for multiple mappings to be configured for the same instance. This means that one or multiple local applications can reach out to one or multiple services using the mTLS Persona to forward the mTLS ID of the local machine, which is the identity principle behind Identity Plus (each device has it's own ID). If the identity abstraction is done at the application level, the added granularity can be achieved by launching multiple instances of mTLS Persona, with specific port mappings and identity mappings. An important note here is that rotation needs to be scheduled for all such mTLS IDs. 

## Building mTLS Persona

mTLS Persona is written in GoLang and expected to run as an executable process. As a GoLang application is is platform independent in the sense that it can be compiled to work with all operating systems and processor architectures. Please adapt it to your use case by building mTLS persona according to your environments specifics:

1. Install GoLang: for Debian based Linux enviornments this would be sudo apt-gets install golang
2. Clone the repository in a local directory: git clone https://github.com/IdentityPlus/mtls-persona.git
3. Open a terminal and change into the local directory
4. Build mTLS Persona: go build mtls-persona.go
5. Use the Identity Plus CLI to obtain an mTLS ID associated with the service (please refer to the Identity Plus CLI Documentation for this)
6. Edit config.json and adapta it to your needs (make the paths match the Identity Destination)
7. Launch mTLS Persona and test it by pointing a client application to it.
8. Make it into a service to launch on startup, before your client applciation.