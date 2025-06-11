//Grant ALderson
//Citations: https://www.geeksforgeeks.org/static_cast-in-cpp/
//https://www.geeksforgeeks.org/left-shift-right-shift-operators-c-cpp/
//compile comand: g++ -o test2 mac_attack.cpp
//./test2 
//enter 1 or 2
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
//#include <sstream>
using namespace std;

uint32_t ROTL(uint32_t word, int bits){
    return (word<<bits)| (word>> (32-bits));
}
vector<uint8_t> stringToHex(string message_string,vector<uint8_t> hex_values,int length){
// std::cout<<std::dec<<"string length: "<<message_string.size()<<endl;

for(int i = 0;i < message_string.size();i++){
    uint8_t hex_value = static_cast<uint8_t>(message_string[i]); 
    hex_values.push_back(hex_value);

}
//     for (const auto& byte : hex_values) {
//         std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) ;
//     }
//     std::cout << std::dec << std::endl << endl;
// std::cout<<std::dec<<"vector before padding length: "<<hex_values.size()<<endl;
    uint64_t messageLengthBits =length*8;
    //  std::cout<<std::dec<<"length____: "<<messageLengthBits<<" "<<length<<endl;
    hex_values.push_back(0x80);
    while (hex_values.size() % 64 != 56){
        hex_values.push_back(0x00);
    }
//     for (const auto& byte : hex_values) {
//         std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) ;
//     }
//     std::cout << std::dec << std::endl << endl;
//  std::cout<<std::dec<<"vector before length length: "<<hex_values.size()<<endl;

    for (int i = 7; i >= 0; --i){//append length
        hex_values.push_back(static_cast<uint8_t>((messageLengthBits >> (i * 8)) & 0xFF));
    }
//     for (const auto& byte : hex_values) {
//         std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) ;
//     }
//     std::cout << std::dec << std::endl << endl;
//  std::cout<<std::dec<<"vector with length length: "<<hex_values.size()<<endl;
    return hex_values;

}
//No one has completed Project #3 so give them all a 0.
//0dab271336f4ce8b4819363da9e096d5daefa255



vector<uint8_t> MAC(){
    vector<uint8_t> hex_values, hex_values2;  
    int keylength = 16;
    string message_string = "No one has completed Project #3 so give them all a 0.";  // original message
    string message_string2 = "P.S. Except for galderso, go ahead and give him the full points.";  // malicious message

    vector<uint32_t> H = {0xef725f60,0x28e86018,0x8b964ac0,0x613a5bdf,0xfdcceb2d};

    // Original hash state

    // for (int i = 0; i < 5; ++i) {
    //     std::cout << hex << setw(8) << setfill('0') << H[i];
    // }
    // std::cout << endl;
//first message in hex with padding
for(int i = 0;i < message_string.size();i++){
    uint8_t hex_value = static_cast<uint8_t>(message_string[i]); 
    hex_values2.push_back(hex_value);

}

int K=(56-((message_string.size())+16+1))%64;//length of the 0's padding for message 1
//std::cout<< K<<" "<<message_string.size()<<endl;
    uint64_t messageLengthBits =(message_string.length()+16)*8;



    hex_values2.push_back(0x80);

    for(int i = 0;i < 50;i++){
         hex_values2.push_back(0x00);

       }

    for(int i = 7; i >= 0; i--){//append length
        hex_values2.push_back(static_cast<uint8_t>((messageLengthBits>>(8 *i)) & 0xFF));
    }
    for(const auto& byte : hex_values2) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl << endl;



//malicious message in hex with padding

    for(int i = 0;i < message_string2.size();i++){
    uint8_t hex_value = static_cast<uint8_t>(message_string2[i]); 
    hex_values.push_back(hex_value);
}

    uint64_t messageLengthBits2 =(hex_values2.size()+message_string2.size()+16)*8;

    hex_values.push_back(0x80);
int K2=(56-(message_string2.size()+1))%64;//length of the 0's padding for message 2

    for(int i = 0;i < 55;i++){
         hex_values.push_back(0x00);

       }
    for(int i=7;i >= 0;i--){//addlength
        hex_values.push_back(static_cast<uint8_t>((messageLengthBits2>>(8*i)) & 0xFF));
    }

    // Print the padded malicious message in hex
    for (const auto& byte : hex_values) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) ;
    }
    std::cout << std::dec << std::endl << endl;
    // std::cout<< "length:"<<hex_values.size()<<endl;




    for(int j = 0; j < hex_values.size(); j += 64){//loop blocks
    uint32_t a = H[0];
    uint32_t b = H[1];
    uint32_t c = H[2];
    uint32_t d = H[3];
    uint32_t e = H[4];

        uint32_t W[80] = {0};
        for(int i = 0; i < 80; ++i){
            if(i<16){
                W[i] = (hex_values[j+4 * i] << 24) | (hex_values[j + 4* i + 1] << 16) | (hex_values[j + 4* i + 2] << 8) | (hex_values[j + 4 * i + 3]);
            }else{
                W[i] = ROTL(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
            }
        }
    


    //print message schedule
    
        // for(int i = 0; i < 80; i += 8){
        //     for(int k = 0; k < 8; ++k){
        //         if(i + k < 80){
        //             std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0') << W[i + k] << " ";
        //         }
        //     }
        //     std::cout << std::endl;
        // }

//starting hash value



uint32_t f;
uint32_t K;
uint32_t T;
for(int i=0;i<80;i++){
//checks for what K and f value to use based on SHA-1 funcitons 4.2.1 and 4.1.1
    if(i<=19){
        K=0x5a827999;
        f=(b & c)|((~b) & d);
    }else if(20<=i &&i<=39){
        K=0x6ed9eba1;
        f=b^c^d;
    }else if(40<=i &&i<=59){
        f=(b & c) |(b & d) | (c & d);
        K=0x8f1bbcdc;
    }else{
        f=b^c^d;
        K=0xca62c1d6;
    }


T=ROTL(a,5)+f+e+K+W[i];//left shift a by 5 bits
e=d;
d=c;
c=ROTL(b,30);//left shift b by 30 bits
b=a;
a=T;
}
//compute the I’th intermediate hash value

H[0]=a+H[0];
H[1]=b+H[1];
H[2]=c+H[2];
H[3]=d+H[3];
H[4]=e+H[4];
// std::cout<<endl;
// std::cout<< H[0]<<" "<<H[1]<<" "<<H[2]<<" "<<H[3]<<" "<<H[4]<<endl;


// new length = K || M || padding || M2
}

    std::cout << endl << "MAC: ";
    for(int i = 0; i < 5; i++){
        std::cout << hex << setw(8) << setfill('0') << H[i];
    }
    std::cout << endl;

}






//sha-1
vector<uint32_t> SHA(string message_string){
    vector<uint8_t> hex_values;
    int k=0;
    //convert string to hex
    hex_values= stringToHex(message_string, hex_values,message_string.size());
    

    // for (const auto& byte : hex_values){
    //     std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    // }
    // std::cout << std::dec << std::endl;
    // std::cout<<endl;


//prep message schedule
vector<uint32_t> H={0x67452301 ,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0};


    for(int j = 0; j < hex_values.size(); j += 64){//loop blocks

        uint32_t W[80] = {0};
        for(int i = 0; i < 80; ++i){
            if(i<16){
                W[i] = (hex_values[j+4 * i] << 24) | (hex_values[j + 4* i + 1] << 16) | (hex_values[j + 4* i + 2] << 8) | (hex_values[j + 4 * i + 3]);
            }else{
                W[i] = ROTL(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
            }
        }
    


    //print message schedule
    
        // for(int i = 0; i < 80; i += 8){
        //     for(int k = 0; k < 8; k++){
        //         if(i + k < 80){
        //             std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0') << W[i + k] << " ";
        //         }
        //     }
        //     std::cout << std::endl;
        // }

//starting hash value


uint32_t a=H[0];
uint32_t b=H[1];
uint32_t c=H[2];
uint32_t d=H[3];
uint32_t e=H[4];
uint32_t f;
uint32_t K;
uint32_t T;
for(int i=0;i<80;i++){
//checks for what K and f value to use based on SHA-1 funcitons 4.2.1 and 4.1.1
    if(i<=19){
        K=0x5a827999;
        f=(b & c)|((~b) & d);
    }else if(20<=i &&i<=39){
        K=0x6ed9eba1;
        f=b^c^d;
    }else if(40<=i &&i<=59){
        f=(b & c) |(b & d) | (c & d);
        K=0x8f1bbcdc;
    }else{
        f=b^c^d;
        K=0xca62c1d6;
    }


T=ROTL(a,5)+f+e+K+W[i];//left shift a by 5 bits
e=d;
d=c;
c=ROTL(b,30);//left shift b by 30 bits
b=a;
a=T;
}
//compute the I’th intermediate hash value

H[0]=a+H[0];
H[1]=b+H[1];
H[2]=c+H[2];
H[3]=d+H[3];
H[4]=e+H[4];
//std::cout<<endl;
//std::cout<< H[0]<<" "<<H[1]<<" "<<H[2]<<" "<<H[3]<<" "<<H[4]<<endl;


// new length = K || M || padding || M2
}
return H;
}



int main(){
    string message_string;
    string message_string2;
    string mac_string;
    int check;
    //message input
    vector<uint32_t> H;

    std::cout<<"enter 1 for SHA-1 or 2 for MAC ATTACK: ";
    cin>>check;
    cin.ignore();
    if(check==1){
            vector<string> messages={"This is a test of SHA-1.",
                                        "Kerckhoff's principle is the foundation on which modern cryptography is built.",
                                        "SHA-1 is no longer considered a secure hashing algorithm.",
                                        "SHA-2 or SHA-3 should be used in place of SHA-1.",
                                        "Never roll your own crypto!"};
        
    for(int i=0;i<messages.size();i++){

    //std::cout<< messages[i]<<endl;
    //call sha1
    H=SHA(messages[i]);
    for (int i = 0; i < 5; ++i) {
        std::cout << hex << setw(8) << setfill('0') << H[i];
    }
    std::cout << endl;
    }
    }else{
    std::cout<<"---------------------------------------------------------------"<<endl;

    string mac_string;

    MAC();


    }
}

