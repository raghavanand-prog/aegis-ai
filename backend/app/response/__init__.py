"""Response actions: requesting containment, and deciding on it.

V9 goes exactly as far as the *decision* and stops. A request records what
somebody wants done and why; an approval records that a second, authorised
person agreed, and what evidence they agreed on. **Nothing in this package
carries an action out**, and a test asserts there is no executor, provider or
handler table anywhere in it.
"""
