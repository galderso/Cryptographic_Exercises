compile command: g++ -o AES AES.cpp
run: ./AES | tr -d '\r'
diff: diff appendix_c.txt <(./AES.exe | tr -d '\r')

I did not look at any AES source code when creating this project.
I used only the resources provided for the logic of the AES and looked 
up syntax for the language i was using for which the links will be bellow:
https://www.geeksforgeeks.org/strings-in-cpp/
https://cplusplus.com/reference/vector/vector/
https://www.geeksforgeeks.org/static_cast-in-cpp/
https://www.geeksforgeeks.org/extended-integral-types-choosing-correct-integer-size-cc/
https://www.geeksforgeeks.org/rotate-bits-of-an-integer/
https://www.geeksforgeeks.org/stdstoi-function-in-cpp/
https://www.geeksforgeeks.org/bitmasking-in-cpp/

My program should pass all test cases from appendix C.