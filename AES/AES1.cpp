//Grant Alderson
//AES encryption and decryption

#include <iostream>
#include <vector>
#include <string>
#include <iomanip>

uint32_t Rcon[10] = {0x01000000,0x02000000,0x04000000, 0x08000000, 0x10000000,0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};


std::vector<uint8_t> key_expansion(std::vector<uint8_t> key,std::vector<uint32_t> w,int Nr,int Nk);
void print2(std::vector<std::vector<uint8_t>> matrix,int i,std::string j);
void print(std::vector<std::vector<uint8_t>> matrix);
/*The Advanced Encryption Standard (AES) algorithm makes use of finite field arithmetic. As such, it is important to read and understand Section 4. In particular, you should implement:
ffAdd()—adds two finite fields (see Section 4.1)
xtime()—multiplies a finite field by x (see Section 4.2.1)
ffMultiply()—uses xtime() to multiply any finite field by any other finite field (see Section 4.2.1)*/
uint8_t xtime(uint8_t A){
    uint8_t result = A << 1;  
    if (A & 0x80) {           
        result ^= 0x1b;       
    }
    return result;
}
uint8_t ffMultiply(uint8_t A, uint8_t B){
    uint8_t Result=0;

    for(int i=0;i<8;i++){ 
        if(B & (1<<i)!=0){ 
        Result ^= A;
        } 
    A= xtime(A);
    B>>=1;
    } 
    return Result;
}

uint8_t ffadd(uint8_t a , uint8_t b){

    return a ^ b;
}
/*Implement key expansion. Notice that the key for use with this algorithm is given as a byte[], but both cipher and invCipher require a word[] as input. The key expansion algorithm (see Section 5.2) performs this conversion. Appendix A gives excellent examples of the key expansion algorithm. The following two functions are needed by this algorithm:
subWord()—takes a four-byte input word and substitutes each byte in that word with its appropriate value from the S-Box. The S-box is provided (see Section 5.1.1)
rotWord()—performs a cyclic permutation on its input word*/
uint32_t subWord(uint32_t byte){


    std::vector<std::vector<uint8_t>> s_box={
        {0x63,0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
        {0xca,0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
        {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
        {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
        {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
        {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
        {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
        {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
        {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
        {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
        {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
        {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
        {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
        {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
        {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
    };
    

    uint32_t changed =0;

    for(int i=0;i<4;i++){//loop through byte

    uint8_t k = (byte>> (8*i))& 0xFF;//move to next hex digits
    
        changed|= (static_cast<uint32_t>(s_box[k >> 4][k & 0x0F]) << (8*i));
    }


return changed;
}
//[a0,a1,a2,a3]->[a1,a2,a3,a0]
uint32_t rotWord(uint32_t byte){
    uint8_t a0 = (byte>> 24) &0xFF; 
    uint8_t a1 = (byte>> 16) &0xFF;
    uint8_t a2 = (byte>> 8) &0xFF;
    uint8_t a3 = byte& 0xFF; 

    uint32_t new_byte = (a1<<24)| (a2<<16) |(a3<<8) | a0;
    return new_byte;
}
/*Implement the cipher function. The cipher function is specified in Section 5.1, and an example is given in Appendix B. Its implementation is quite simple once the following four transformations are created:
subBytes()—This transformation substitutes each byte in the state with its corresponding value from the S-Box.
shiftRows()—This transformation performs a circular shift on each row in the state (see Section 5.1.2).
mixColumns()—This transformation treats each column in state as a four-term polynomial. This polynomial is multiplied (modulo another polynomial) by a fixed polynomial with coefficients (see Sections 4.3 and 5.1.3).
addRoundKey()—This transformation adds a round key to the state using XOR.*/


std::vector<std::vector<uint8_t>> subBytes(std::vector<std::vector<uint8_t>> matrix){
    std::vector<std::vector<uint8_t>> s_box={
        {0x63,0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
        {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
        {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
        {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
        {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
        {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
        {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
        {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
        {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
        {0x60, 0x81, 0x4f, 0xdc,0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
        {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
        {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
        {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
        {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
        {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
    };

    std::vector<std::vector<uint8_t>> new_matrix=matrix;
    //print(new_matrix);
    
    for(int j=0;j<matrix.size();j++){

    for(int i=0;i<matrix[0].size();i++){//loop through byte
        uint8_t byte=matrix[j][i];
        new_matrix[j][i]=s_box[byte >> 4][byte & 0x0F];
    }
    }
//printMatrix(new_matrix);
return new_matrix;
}

std::vector<std::vector<uint8_t>> shiftRows(std::vector<std::vector<uint8_t>> matrix){
std::vector<std::vector<uint8_t>> new_matrix = matrix;

for(int i=0;i<matrix[0].size();i++){
    new_matrix[i][1]=matrix[(i+1)%(matrix[0].size())][1];
}

for(int i=0;i<matrix[0].size();i++){
    new_matrix[i][2]=matrix[(i+2)%(matrix[0].size())][2];
}

for(int i=0;i<matrix[0].size();i++){
    new_matrix[i][3]=matrix[(i+3)%(matrix[0].size())][3];
}



return new_matrix;
}

std::vector<std::vector<uint8_t>> mixColumns(std::vector<std::vector<uint8_t>> matrix){

 std::vector<std::vector<uint8_t>> new_matrix = matrix;

for(int i=0;i<4;i++){ 
    new_matrix[i][0]= ffMultiply(0x02, matrix[i][0])^ffMultiply(0x03,matrix[i][1])^matrix[i][2]^matrix[i][3]; 
    new_matrix[i][1]= matrix[i][0]^ ffMultiply(0x02, matrix[i][1])^ ffMultiply(0x03, matrix[i][2])^ matrix[i][3]; 
    new_matrix[i][2]= matrix[i][0]^matrix[i][1]^ ffMultiply(0x02, matrix[i][2])^ ffMultiply(0x03, matrix[i][3]); 
    new_matrix[i][3]= ffMultiply(0x03, matrix[i][0])^matrix[i][1]^matrix[i][2]^ ffMultiply(0x02, matrix[i][3]); 

} 

return new_matrix;
}

std::vector<std::vector<uint8_t>> addRoundKey(std::vector<std::vector<uint8_t>> matrix, std::vector<uint8_t> key){

    for(int i=0;i<matrix[0].size();i++){
        for(int j=0;j<4;j++){

            matrix[j][i]^= key[(j*4)+i];

        }

    }
    return matrix;
}
/*Implement the invCipher function. This function is specified in Section 5.3. It reverses the effect of the cipher function. Its implementation is quite simple once the following three transformations are created:
invSubBytes()—This transformation substitutes each byte in the state with its corresponding value from the inverse S-Box, thus reversing the effect of a subBytes() operation.
invShiftRows()—This transformation performs the inverse of shiftRows() on each row in the state (see Section 5.3.1).
invMixColumns()—This transformation is the inverse of mixColumns (see Section 5.3.3).
After implementing these functions, you will need to demonstrate that your solution works by providing a program that runs the test cases described in Appendix C of FIPS 197Links to an external site.. When your code is run, it should, without any input from the command line or command line options, print out all of the test cases in Appendix C of the FIPS specification, with the debug information for each round. Your project will be graded by diffing its output against this file Download this filescraped from Appendix C. This file is provided so you can fine-tune your output to ensure your output is correctly formatted.
*/
std::vector<std::vector<uint8_t>> invSubBytes(std::vector<std::vector<uint8_t>> matrix){
    std::vector<std::vector<uint8_t>> inv_sbox={
        {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
        {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
        {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
        {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
        {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
        {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
        {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
        {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
        {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
        {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
        {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
        {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
        {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
        {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
        {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
        {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
    };

    std::vector<std::vector<uint8_t>> new_matrix=matrix;
    uint8_t byte;
    for(int j=0;j<matrix.size();j++){

    for(int i=0;i<matrix[0].size();i++){//loop through byte
        byte=matrix[j][i];
        new_matrix[j][i]=inv_sbox[(byte >> 4)][byte & 0x0F];
    }
    }

return new_matrix;
}


std::vector<std::vector<uint8_t>> invShiftRows(std::vector<std::vector<uint8_t>> matrix){
std::vector<std::vector<uint8_t>> new_matrix = matrix;

for(int i=0;i<matrix[0].size();i++){//row2
    new_matrix[(i+1)%(matrix[0].size())][1]=matrix[i][1];
}

for(int i=0;i<matrix[0].size();i++){//row3
    new_matrix[(i+2)%(matrix[0].size())][2]=matrix[i][2];
}

for(int i=0;i<matrix[0].size();i++){//row4
    new_matrix[(i+3)%(matrix[0].size())][3]=matrix[i][3];
}
return new_matrix;
}


std::vector<std::vector<uint8_t>> invMixColumns(std::vector<std::vector<uint8_t>> matrix){
 std::vector<std::vector<uint8_t>> new_matrix=matrix;
for(int i=0;i<4;i++){ 
    new_matrix[i][0]= ffMultiply(0x0e, matrix[i][0])^ffMultiply(0x0b,matrix[i][1])^ffMultiply(0x0d,matrix[i][2])^ffMultiply(0x09,matrix[i][3]); 
    new_matrix[i][1]= ffMultiply(0x09,matrix[i][0])^ ffMultiply(0x0e, matrix[i][1])^ ffMultiply(0x0b, matrix[i][2])^ ffMultiply(0x0d,matrix[i][3]); 
    new_matrix[i][2]= ffMultiply(0x0d,matrix[i][0])^ffMultiply(0x09,matrix[i][1])^ ffMultiply(0x0e, matrix[i][2])^ ffMultiply(0x0b, matrix[i][3]); 
    new_matrix[i][3]= ffMultiply(0x0b, matrix[i][0])^ffMultiply(0x0d,matrix[i][1])^ffMultiply(0x09,matrix[i][2])^ ffMultiply(0x0e, matrix[i][3]); 

} 

return new_matrix;
}


int main() {

    std::vector<std::string> keys={"000102030405060708090a0b0c0d0e0f", 
    "000102030405060708090a0b0c0d0e0f1011121314151617",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"};

    std::vector<int> rounds={10,12,14};
    std::string in_string="00112233445566778899aabbccddeeff";
    std::vector<std::vector<uint8_t>> state_diagram(4,std::vector<uint8_t>((in_string.length()/2)/4));

    for (int i=0;i <in_string.length()/2;i++) {//setup state diagram
        state_diagram[i / 4][i%4] = static_cast<uint8_t>(std::stoi(in_string.substr(i * 2, 2), nullptr, 16));

    } 

for(int k=0;k<3;k++){//loop through the 3 examples
    //initialize
    int Nr =rounds[k];
    std::string key_string=keys[k];
    int Nk=(key_string.length()/2)/4;
    int Nb =(key_string.length()/2)/4;

    std::cout<<std::dec<<"C."<<k+1<<"   AES-"<<key_string.length()*4<<" (Nk="<<Nk<<", Nr="<<Nr<<")\n"<<std::endl;


 
    std::cout <<"PLAINTEXT:          "<<in_string<<std::endl;
    std::cout <<"KEY:                "<<key_string<<std::endl;
    std::cout<<"\nCIPHER (ENCRYPT):"<<std::endl;
    print2(state_diagram,0,"input ");



    //key expansion------------------------------------------------------------------
    //expands the key to use in each round
    std::vector<std::vector<uint8_t>> key(4,std::vector<uint8_t>(key_string.length()/2));
    std::vector<uint8_t> byte_vector;
    std::cout<< std::setfill(' ')<<"round[ "<<0<<"]."<<std::setw(10)<< std::left<<"k_sch ";
    for (size_t i = 0; i< key_string.length(); i += 2){
        std::string byte_string = key_string.substr(i, 2); 
        uint8_t byte=static_cast<uint8_t>(std::stoi(byte_string, nullptr, 16)); 
        byte_vector.push_back(byte);
        if(i<32){
        std::cout<< byte_string;
    }
    }


    std::cout<<std::endl;
    std::vector<uint32_t> w(Nb*(Nr+1));
    std::vector<uint8_t> key_expan(Nb*(Nr+1));
    key_expan=key_expansion(byte_vector, w,Nr,Nk);


//-------------------------------------------------------------------------------------

    std::vector<uint8_t> temp(key_expan.begin(),key_expan.begin()+16);
    state_diagram=addRoundKey(state_diagram,temp);

   
    std::cout<< std::setfill(' ')<<"round[ "<<1<<"]."<<std::setw(10)<< std::left<<"start ";

    for(int j=0;j<temp.size();j++){
        std::cout <<std::hex << std::setw(2) << std::setfill('0') << (int)temp[j];
    }
    std::cout<<std::endl;
    for(int i=1;i<Nr;i++){//each round loop
        state_diagram=subBytes(state_diagram);

        print2(state_diagram,i,"s_box ");
        state_diagram=shiftRows(state_diagram);

        print2(state_diagram,i,"s_row ");
        state_diagram=mixColumns(state_diagram);

        print2(state_diagram,i,"m_col ");
        std::vector<uint8_t> temp2(key_expan.begin()+((i)*16),key_expan.begin()+((i+1)*16));
    if(i>=10){
    std::cout<< std::setfill(' ')<<std::dec<<"round["<<i<<"]."<<std::setw(10)<< std::left<<"k_sch ";
    }else{
    std::cout<< std::setfill(' ')<<std::dec<<"round[ "<<i<<"]."<<std::setw(10)<< std::left<<"k_sch ";
    }
        for(int j=0;j<temp2.size();j++){
      std::cout<< std::right<<std::hex << std::setfill('0')<< std::setw(2)<<(int)temp2[j];
        }
        state_diagram=addRoundKey(state_diagram,temp2);
        std::cout<<std::endl;
        print2(state_diagram,i+1,"start ");
        
    }
    state_diagram=subBytes(state_diagram);
    print2(state_diagram,Nr,"s_box ");
    state_diagram=shiftRows(state_diagram);
    print2(state_diagram,Nr,"s_row ");

    std::vector<uint8_t> temp3(key_expan.begin()+(Nr*16),key_expan.begin()+((Nr+1)*16));
    if(Nr>=10){
        std::cout<< std::setfill(' ')<<std::dec<<"round["<<Nr<<"]."<<std::setw(10)<< std::left<<"k_sch ";
    }else{
        std::cout<< std::setfill(' ')<<std::dec<<"round[ "<<Nr<<"]."<<std::setw(10)<< std::left<<"k_sch ";
    }
    for(int j=0;j<temp3.size();j++){
        std::cout<< std::right<<std::hex << std::setfill('0')<< std::setw(2)<<(int)temp3[j];
    }
    state_diagram=addRoundKey(state_diagram,temp3);
    std::cout<<std::endl;

    print2(state_diagram,Nr,"output ");


    //decryption------------------------------------------------------------------
    std::cout<<std::endl;
    std::cout<<"INVERSE CIPHER (DECRYPT):"<<std::endl;

    print2(state_diagram,0,"iinput ");

    std::cout<< std::setfill(' ')<<std::dec<<"round[ "<<0<<"]."<<std::setw(10)<< std::left<<"ik_sch ";
    for(int j=0;j<temp3.size();j++){
        std::cout << std::right<<std::hex << std::setw(2) << std::setfill('0') << (int)temp3[j];
    }
        

    state_diagram=addRoundKey(state_diagram,temp3);
    std::cout<<std::endl;
    print2(state_diagram,1,"istart ");

   
    for(int j=Nr-1;j>=1;j--){//loop rounds
        state_diagram=invShiftRows(state_diagram);
        print2(state_diagram,Nr-j,"is_row ");
        state_diagram=invSubBytes(state_diagram);
        print2(state_diagram,Nr-j,"is_box ");
        
       
        std::vector<uint8_t> temp4(key_expan.begin()+(j*16),key_expan.begin()+((j+1)*(16)));
        if(Nr-j>=10){
            std::cout<< std::setfill(' ')<<std::dec<<"round["<<Nr-j<<"]."<<std::setw(10)<< std::left<<"ik_sch ";
        }else{
            std::cout<< std::setfill(' ')<<std::dec<<"round[ "<<Nr-j<<"]."<<std::setw(10)<< std::left<<"ik_sch ";
        }
        for(int i=0;i<temp4.size();i++){
            std::cout<< std::right<<std::hex <<  std::setfill('0')<<std::setw(2)<<(int)temp4[i];
        }
        std::cout<<std::endl;
        state_diagram=addRoundKey(state_diagram,temp4);
        print2(state_diagram,Nr-j,"ik_add ");
        state_diagram=invMixColumns(state_diagram);
        print2(state_diagram,Nr+1-j,"istart ");

    }

    state_diagram=invShiftRows(state_diagram);

    print2(state_diagram,Nr,"is_row ");
    state_diagram=invSubBytes(state_diagram);

    print2(state_diagram,Nr,"is_box ");
 

    std::vector<uint8_t> temp5(key_expan.begin(),key_expan.begin()+(Nb*4));
    if(Nr>=10){
    std::cout<< std::setfill(' ')<<std::dec<<"round["<<Nr<<"]."<<std::setw(10)<< std::left<<"ik_sch ";
    }else{
    std::cout<< std::setfill(' ')<<std::dec<<"round[ "<<Nr<<"]."<<std::setw(10)<< std::left<<"ik_sch ";
    }
        for(int j=0;j<16;j++){
        std::cout << std::right<<std::hex << std::setw(2) << std::setfill('0') << (int)temp5[j];
        }
        std::cout<<std::endl;
    state_diagram=addRoundKey(state_diagram,temp5);
    //std::cout<<std::dec<<"round[ "<<Nr<<"]."<<"ioutput ";
    print2(state_diagram,Nr,"ioutput ");

    if(k<2){
    std::cout<<std::endl;
    }
}

    return 0;
}




//Key expansion
//based on fips document sudocode

//
std::vector<uint8_t> key_expansion(std::vector<uint8_t> key,std::vector<uint32_t> w,int Nr, int Nk){
std::vector<uint8_t> key_expan;
uint32_t temp;
int i=0;

    while(i<Nk){
        w[i]=(static_cast<uint32_t>(key[4*i])<<24)|(static_cast<uint32_t>(key[(4*i)+1])<<16)|(static_cast<uint32_t>(key[(4*i)+2])<<8)|static_cast<uint32_t>(key[(4*i)+3]);
 
        i++;
        
    }
    

    while(i<4*(Nr+1)){
        temp = w[i-1];
        //std::cout<< "temp:"<<temp<<std::endl;
        if(i%Nk==0){
            temp = subWord(rotWord(temp))^Rcon[i / Nk-1];
        //std::cout<< "rcon:"<<Rcon[i / Nk-1]<<std::endl;
        //std::cout<< "after xor:"<<temp<<std::endl;
        }else if(Nk>6 && i%Nk==4){
            temp =subWord(temp);
        }
        //std::cout<< "w[i-Nk]:"<<w[i-Nk]<<std::endl;
        w[i]=w[i-Nk]^temp;
        //std::cout<< "w[i] xor:"<<w[i]<<std::endl;
        i=i+1;
    }


for( int j=0;j<w.size();j++){
    key_expan.push_back(static_cast<uint8_t>(w[j]>> 24& 0xFF));
    key_expan.push_back(static_cast<uint8_t>(w[j]>> 16& 0xFF));
    key_expan.push_back(static_cast<uint8_t>(w[j]>> 8& 0xFF));
    key_expan.push_back(static_cast<uint8_t>(w[j]&0xFF));

}

return key_expan;
}


void print(std::vector<std::vector<uint8_t>> matrix){//prints 4 by4

    for (int i = 0; i < matrix.size(); i++) {
        for (int j = 0; j < 4; j++) {
            std::cout <<std::hex << std::setw(2) << std::setfill('0') << (int)matrix[j][i];
        }
            std::cout<<std::endl;
    }
    std::cout<<std::endl;

}
//prints like expected output
void print2(std::vector<std::vector<uint8_t>> matrix, int i, std::string j){
if(i>=10){
std::cout<<std::dec<<"round["<<i<<"]." << std::setfill(' ')<<std::setw(10)<< std::left <<j;
}else{
std::cout<<std::dec<<"round[ "<<i<<"]." << std::setfill(' ')<<std::setw(10)<< std::left <<j;
}

    for (int i = 0; i < matrix.size(); i++) {
        for (int j = 0; j < 4; j++) {
            std::cout << std::right<<std::hex <<std::setw(2) << std::setfill('0') << (int)matrix[i][j];
        }
            //std::cout<<std::endl;
    }
    std::cout<<std::endl;

}



