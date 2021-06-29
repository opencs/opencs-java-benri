# opencs-java-benri

**OpenCS Java Benri** is a small library that contains open source versions of
some of **OpenCS's** utility functions used by some of our products.

This library has been released to help our partners and customers to implement
some basic functionalities used by us and also as a support library for some of
our open source tools.

Although this library is based on some functionalities used by our commercial
products, it is not guaranteed to be compatible with those implementations.

## Dependencies

This library is written for **Java 8** with no additional dependencies. The only
external dependency used by this project is **JUnit** for testing purposes.

## Contents

For now, this library contains the following functionalities:

- Memory cleanup utilities;
- A basic String obfuscator loosely based on **Fernet** algorithm implemented
  by the Python's Cryptography library (see
  [Fernet (symmetric encryption)](https://cryptography.io/en/latest/fernet/));
  
Other functionalities may be included to this library on requests by our partners
and customers.

## License

This software is licensed under the **BSD 3-Clause License**.

## Disclaimer

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
