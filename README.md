# libwebsock2

C Websocket Library

libwebsock is a websocket library written in C that is meant to be simple, powereful, portable and easy to use.

libwebsock v2.0.0 continues on the same path as v1 in terms of ease of use and implementation, but aims to resolve a lot of the performance issues related to the original release. With the introduction of a scheduler and agent workers, as well as enhancements in connection handling, libwebsock2 aims to be the simplest yet most powerful websocket library available. 

## New features in libwebsock v2.0.0
* Scheduler / Agent Implementation - libwebsock now uses a scheduler with agents to ensure maximum performance across multiple cores.  
* Multiple Event Bases - Clients are now distributed across multiple event bases on multiple cores. This ensures libevent is being used at maximum efficiency.
* Improved Event Handling - Events (messages, control frames etc) are now handled by the scheduler/agents. This is a major improvement over the original method of creating a new thread per event.
* Unique Client Tags - libwebsock2 enhances the ability to track client sessions and send messages specifically to targeted connections. libwebsock1 required the sessions be tracked in user-land. Our competitor websocket library, libwebsockets, implements a feature to assign a unique ID to the session, but has no way to interact with it outside of a received message. libwebsock2 introduces the ability to assign a unique identifier to the client state and send messages using that unqiue identifier,  making things like chat and instant messaging even easier to accomplish for user-land code. 

## Coming Soon
* VM/GC Implementation - Right now, we statically clean up all memory. This is effective, but makes future enhancements to libwebsock difficult. A VM/GC is being tested to improve memory management and make it easier to build on.
* Dynamic Memory Allocation - The scheduler requires jobs be wrapped with a job wrapper before passing them off. Each job requires a malloc() to create and prepare the wrapper. The goal is to pre-allocate X amount of wrappers in advance (50?) and use the available wrappers for the jobs. If not enough wrappers are available, the goal is to allocate another X amount of wrappers, and free them up once the demand for job wrappers is decreased. A good algorithm for this is still being worked on.

## Thanks and Credits

libwebsock was originally developed and conceptually designed by Payden Kyle Sutherland, who passed away on September 24, 2014. His idea of making it easy to use paved the way to what is now libwebsock2. If not for his original idea, I would not have picked up and continued development on it. For that reason, this development is devoted to Payden, who was a brilliant individual whose time here was not long enough.
