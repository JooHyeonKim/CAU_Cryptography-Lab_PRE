# 🗝️ CAU_Cryptography-Lab_PRE
중앙대학교 Private Artificial Intelligence and Cryptography Lab_ 학부연구생 <br/><br/>

<div align="center">
  🗝️ 동형암호란 🗝️
</div>
<img width="900" alt="스크린샷 2023-07-20 오후 7 03 00" src="https://github.com/JooHyeonKim/CAU_Cryptography-Lab_PRE/assets/56497471/1d693739-8ebe-4f53-8a15-cb51c4bea71a">


<h4><b>🗓️ 활동기간 🗓️</b></h4>
2023.06.26 ~ 
<br/><br/>

<h4><b> 🔗 참고 사이트 🔗</b></h4>  
* PAICLAB 홈페이지 : https://sites.google.com/view/paiclab <br/>
* 노션 링크 : https://www.notion.so/5bb3b3abac3f4ed1a2720faa270875f9?v=ebb4e44e3b0c498890a9a5a5c561c1ea&pvs=4

<br/>

<h4><b>🛠 Tech Stack 🛠</b></h4>
<img src="https://img.shields.io/badge/c++-00599C?style=flat-square&logo=c%2B%2B&logoColor=white"/></a> 
<br/>

## week1
📃 task : microsoft SEAL library 설치 및 실행

## week2
📃 task : SEAL library의 5)ckks_basics.cpp와 6)rotation.cpp 코드 이해 및 분석

## week3
📃 task : SEAL library의 5)ckks_basics.cpp와 6)rotation.cpp 코드를 참고하여 (x+1)^2 * (x^2+1)을 계산 후 2 step 왼쪽으로 rotation하는 코드 작성<br/><br/>
&nbsp;&nbsp;&nbsp;      - polymodulust degree : 2^14<br/>
&nbsp;&nbsp;&nbsp;      - 초기 scale = 2^50<br/>
&nbsp;&nbsp;&nbsp;      - {60, 50, 50, 50, 50, 60}<br/>


9_ckks_task.cpp 실행결과
<img width="500" alt="스크린샷 2023-07-20 오후 7 03 00" src="https://github.com/JooHyeonKim/CAU_Cryptography-Lab_PRE/assets/56497471/385f34bd-6af4-457c-a915-1239f7e3745c">

## week4
📃 task : OpenFHE 설치 후 (x+1)^2 * (x^2+1)을 계산 후 2 step 왼쪽으로 rotation하는 코드 작성 <br/>

🔗 OpenFHE documentation : https://openfhe-development.readthedocs.io/en/latest/

## week5
📃 task : OpenFHE의 Cipertext를 class로 만들어서 scale 및 decryption vector 추적 </br></br>
ex. Cipertext ct </br>
    ct.showDetail </br>
-> scale : ~~ </br>
-> decryption : ~~</br>
-> original : ~~</br>
* 암호화한 시점에 보여주고, 연산할수록 얼마나 차이가 나는지 확인할 수 있도록 한다.</br>



                   










