#Grant Alderson
#This program performs perimage and collision attacks on a sha-1 hash
#Citations: https://www.geeksforgeeks.org/python-pandas-dataframe/
#https://www.geeksforgeeks.org/python-seaborn-tutorial/
#https://www.geeksforgeeks.org/hashlib-module-in-python/
#https://www.geeksforgeeks.org/python-generate-random-string-of-given-length/
#https://www.geeksforgeeks.org/matplotlib-tutorial/

import hashlib
import random
import string
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

def wrapper(message:str, bits:int)->int:#hash string
    hash=hashlib.sha1(message.encode("utf-8")).hexdigest()
    binary= bin(int(hash,16))
    return binary[2:bits+2]


sizes =[8, 10, 12, 14, 16, 18, 20, 22]
iteration =0
collision=[]
preimage=[]
preimagesizes=[]
collisionsizes=[]

for j in range(50):#samples

    
    for i in sizes:#preimage
        truncated=wrapper(''.join(random.choices(string.ascii_letters + string.digits, k=64)),i)#generates random string of size k
        
        iteration =0
        while True:
            binary= ''.join(random.choice('01') for _ in range(i))
            if truncated == binary:#match found
                preimagesizes.append(i)
                preimage.append(iteration)
                break
            iteration=iteration+1
    
    for i in sizes:#collision
        
        iteration =0
        binaryArray=[]
        while True:
            truncated=wrapper(''.join(random.choices(string.ascii_letters + string.digits, k=16)),i)
            if truncated in binaryArray:#match found

                collisionsizes.append(i)
                collision.append(iteration)
                break
            else:
                binaryArray.append(truncated)
            iteration=iteration+1

df = pd.DataFrame({#collision
    'sizes': collisionsizes,
    'collision iterations': collision,
    'preimage iterations': preimage
})

val=[df[(df['sizes'] == 8)],
     df[(df['sizes'] == 10)],
     df[(df['sizes'] == 12)],
     df[(df['sizes'] == 14)],
     df[(df['sizes'] == 16)],
     df[(df['sizes'] == 18)],
     df[(df['sizes'] == 20)],
     df[(df['sizes'] == 22)]]
#average
val2=[val[0]['collision iterations'].mean(),
      val[1]['collision iterations'].mean(),
      val[2]['collision iterations'].mean(),
      val[3]['collision iterations'].mean(),
      val[4]['collision iterations'].mean(),
      val[5]['collision iterations'].mean(),
      val[6]['collision iterations'].mean(),
      val[7]['collision iterations'].mean(),]
val3=[val[0]['preimage iterations'].mean(),
      val[1]['preimage iterations'].mean(),
      val[2]['preimage iterations'].mean(),
      val[3]['preimage iterations'].mean(),
      val[4]['preimage iterations'].mean(),
      val[5]['preimage iterations'].mean(),
      val[6]['preimage iterations'].mean(),
      val[7]['preimage iterations'].mean(),]

#bar graphs
print(val2)
print(val3)
plt.figure(figsize=(14, 6))
plt.subplot(1, 2, 1)
sns.boxplot(x='sizes', y='collision iterations', data=df)
for i in range(8):
    plt.scatter([i], [val2[i]], color='orange', s=10, zorder=10)  
expected = 1.1774*(2**(np.array(sizes)/2))

plt.plot(np.arange(len(sizes)), expected, label=r'$2^n/2$', color='red', linestyle='--', zorder=10)
plt.yscale('log')  
plt.title('Box Plot of Collision Iterations by Size')
plt.xlabel('Sizes')
plt.ylabel('Collision Iterations (Log Scale)')


plt.subplot(1, 2, 2)
sns.boxplot(x='sizes', y='preimage iterations', data=df)
for i in range(8):
    plt.scatter([i], [val3[i]], color='orange', s=10, zorder=10)
expected2 = 2**np.array(sizes)
plt.plot(np.arange(len(sizes)), expected2, label=r'$2^n$', color='red', linestyle='--', zorder=10)
plt.yscale('log')  
plt.title('Box Plot of Preimage Iterations by Size')
plt.xlabel('Sizes')
plt.ylabel('Preimage Iterations (Log Scale)')
plt.tight_layout()
plt.show()


#scatter plots
plt.figure(figsize=(14, 6))
plt.subplot(1, 2, 1)
sns.scatterplot(x=df['sizes'], y=df['collision iterations'])
plt.yscale('log')  
plt.title('Scatter Plot for Collision Iterations')
plt.xlabel('Sizes')
plt.ylabel('Collision Iterations')


plt.subplot(1, 2, 2)
sns.scatterplot(x=df['sizes'], y=df['preimage iterations'])
plt.yscale('log')  
plt.title('Scatter Plot for Preimage Iterations')
plt.xlabel('Sizes')
plt.ylabel('Preimage Iterations')

plt.tight_layout()
plt.show()