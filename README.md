# rot64-cipher
A silly little cipher I invented, combining the caesar cipher with base64 encoding.

The rot64-cipher takes a plaintext message along with a number of total iterations. In
each iteration, the plaintext message is caesar-shifted by 1, and then base64 encoded.

Then, the next iteration will caesar-shift the previous base64 string by 1, and base64 encode it again.

The process repeats for the specified # of iterations (rotations).

### To-Do
For added security, a symmetric key or password can be used such that for each iteration,
the string gets caesar-shifted a number of times corresponding to the value of the current character
in the key.  

### Credits!
The base64 library I used for this project is Rene Nyffenegger's
[cpp-base64](https://github.com/ReneNyffenegger/cpp-base64). Very useful!
