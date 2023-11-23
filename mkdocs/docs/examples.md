# Examples

## Authorization code flow with PKCE

Test client running at `https://goiabada-test-client:8090/`.

code_verifier: `c6LMEl3UI3S3lTM-Uzhtr0YKB3xFvTz1K0hrLw2pXec`

Request (GET /auth/authorize):

```
https://localhost:8100/auth/authorize?
client_id=test-client-1&
code_challenge=qOhSr_Q2ZVrhCyV5pXffXjwWyQo4hJiChZinvU2D2t0&
code_challenge_method=S256&
redirect_uri=https%3A%2F%2Fgoiabada-test-client%3A8090%2Fcallback.html&
response_type=code&
response_mode=query&
state=dILs42Ft-oN0FkMUHTl3fzrMfwvZoCsU62-KLz-DhFc&
nonce=dPjdYJWSH6TgE14BTWPm9FC4La7tNqCkpmS7GVEx9lA&
scope=openid+email
```

Response from auth server:

```
https://goiabada-test-client:8090/callback.html?
code=ff1d6cb9dd124064aba23b6fb3ee5766TAZtZjWiIs6JT9zm3mVOmjKVlwx_sB8-LLj8M1KdwA5LR19KNVGdjGShhsUGIOS1bj61Ew7Ipk7SRyxaaFMvRMHi8zoSfZP_&
state=dILs42Ft-oN0FkMUHTl3fzrMfwvZoCsU62-KLz-DhFc
```

Token request (POST /auth/token)

"content-type": `application/x-www-form-urlencoded;charset=UTF-8`

```{.py3 title="request body"}
redirect_uri=https%3A%2F%2Fgoiabada-test-client%3A8090%2Fcallback.html&
code_verifier=c6LMEl3UI3S3lTM-Uzhtr0YKB3xFvTz1K0hrLw2pXec&
code=ff1d6cb9dd124064aba23b6fb3ee5766TAZtZjWiIs6JT9zm3mVOmjKVlwx_sB8-LLj8M1KdwA5LR19KNVGdjGShhsUGIOS1bj61Ew7Ipk7SRyxaaFMvRMHi8zoSfZP_&
grant_type=authorization_code&
client_id=test-client-1&
client_secret=_aNFH73b42adzow1j3pklASrx9F1HCsXIUmgeMU6ktJR-xCbbPag4MzOPef2
```

Token response:

```javascript
{
    "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVlYjlmZDk4LWIzOWQtNDBiMC04NGVhLWFhMjc0ZWY3M2VkMyIsInR5cCI6IkpXVCJ9.eyJhY3IiOiJ1cm46Z29pYWJhZGE6cHdkOm90cF9pZnBvc3NpYmxlIiwiYW1yIjoicHdkIiwiYXVkIjoiYXV0aHNlcnZlciIsImF1dGhfdGltZSI6MTcwMDc1OTM4MiwiZXhwIjoxNzAwNzU5Njg1LCJpYXQiOjE3MDA3NTkzODUsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0OjgxMDAiLCJqdGkiOiI3OGVjMzIyZi00NDEyLTQ3MzEtODkzYi1jYWU3MThlZDczODYiLCJub25jZSI6ImRQamRZSldTSDZUZ0UxNEJUV1BtOUZDNExhN3ROcUNrcG1TN0dWRXg5bEEiLCJzY29wZSI6Im9wZW5pZCBlbWFpbCBhdXRoc2VydmVyOnVzZXJpbmZvIiwic2lkIjoiNGU3YTlkYzYtYjFlMy00NGJmLTliNzktMWZhNTk0NjM2N2I5Iiwic3ViIjoiZTIwYzM5MzktY2E3My00MTJhLThmODgtMmYzMTAxYTZkZDRkIiwidHlwIjoiQmVhcmVyIn0.OOs-GPF3Oh8xhDdZ9AhMk92S70gOsV6syJMc-cL707qdNg6XTUZqM0mpFGQXBoRv02Yt5IKtOStFSc8qP2jrSHtc_FDt_pXrhdM7TMzaS_EAN20Yd9punBejYI84a5GDlOnSu7D3yo-VBVE7h-LBseC5etHAfZBOGWDAHPNnHVjeQwQ0RFJh2Nbxt7kfmq3Lm6InaacCyg_oIGePvBW7AS1HUsODESCgHui4AEUgcnLi5cfxGTOdkxan5xG4d8I4b3HVDNRc0MKt79CnwOdq7puUKqm1mhNehSXDYnnHn_V5Siboxrtp7OqSroAF6VBbBbSH0L5jDk6BfrTraSniYTGSKOsySWoKsoBE9Okf2W57Mx4rLpQGwnae__OEjl9CukVV9NLSoIbz3qdJSszVPjO2gY5qkIxC1Y61vuOhtIMXi6BxA5n-mqVQuNlNSv5xWCZT6PFKvtB4mjnnKfJpgyeKu4_Zo6ca5Znn4TlNnRNX0VMrVoSiivYNUvJWgvCd-xItHrQARpJyWcrri8UHmeYSpYEcmY7Tlbw1xxnJvzsmsXSouww09-GtXQJxau_zL9btxu27qKGMzU_7afCoaEX-g9ExpdEstsq3AmVaclP9L3lsbYnOLgBIfViPlWQIoIy5Sm2vCzJ3qu5L76U5AA-OUrfZDcan_n7Hqf1_nxY",
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVlYjlmZDk4LWIzOWQtNDBiMC04NGVhLWFhMjc0ZWY3M2VkMyIsInR5cCI6IkpXVCJ9.eyJhY3IiOiJ1cm46Z29pYWJhZGE6cHdkOm90cF9pZnBvc3NpYmxlIiwiYW1yIjoicHdkIiwiYXVkIjoidGVzdC1jbGllbnQtMSIsImF1dGhfdGltZSI6MTcwMDc1OTM4MiwiZW1haWwiOiJzb21lb25lQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJleHAiOjE3MDA3NTk2ODUsImlhdCI6MTcwMDc1OTM4NSwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODEwMCIsImp0aSI6IjM2NDZjMmY2LWJhMGMtNGU4Ny04MDBkLTkwZmJjYjQ5ZTJiZCIsIm5vbmNlIjoiZFBqZFlKV1NINlRnRTE0QlRXUG05RkM0TGE3dE5xQ2twbVM3R1ZFeDlsQSIsInNpZCI6IjRlN2E5ZGM2LWIxZTMtNDRiZi05Yjc5LTFmYTU5NDYzNjdiOSIsInN1YiI6ImUyMGMzOTM5LWNhNzMtNDEyYS04Zjg4LTJmMzEwMWE2ZGQ0ZCIsInR5cCI6IklEIn0.NAwBM-Rm1OF8q8qjwMT5Su5RTUQSSy-P8kEQQerKks1RMuRddQ4WYW5GHSKfYdMl0PhBVOCkyjTlZgaSGoeUCxTkipOCQ65lsTc3hXf6Oc5dV6CFmXlCSlQQe1rKNg8UUG82F-Sq9qPmbro6ttEQJbCx-_3Iw8SVo-OzeFbbZ6r-aNlbbQm8TlHhGROYvL9BFqKiWEEwKlQHCdISHZEb251qOMEndLbWG8KBWKYWNk6MHkxeUZjFG0S1Hs2dcbg5LkY-WZqnYenNXU1D-ACYhfMvoyGt_WK6kIf3FWvC2xJpjbNcgYdlibzcoTphkr_MrCvU7zX2qLGWrmgEdzlEJyIbJuTAPiEmLUE8S0uRCMsZH-rSfbx8MqAkhYSQuS0eKkTJH2qwdpsPJjkr3MhSg1TKGioovf2QL1snxXU_53AMOiypDuPCnBGhO3qJC0BREfR2vqIV2halqyUihGdQyfhuAnujf3u3En6H3HozJp6dPItZgjivMHeGVJr0zLt3YzCVHHXt9yU0zIxL-stTMUugK7HFZYxJFFMgLzgooo---a25u5SyPoWCZslrc_yXpYhClS0LWCbCjJdPXbblHm-ZA6ldqiR9LyunnyvGIeO84ln9zUH584vOrVxuyUt2z7FIkcHFnEjgfbO5zoA5WA2wqp-7qulMzLFGIVV7Bdg",
    "token_type": "bearer",
    "expires_in": 300,
    "refresh_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVlYjlmZDk4LWIzOWQtNDBiMC04NGVhLWFhMjc0ZWY3M2VkMyIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo4MTAwIiwiZXhwIjoxNzAwNzY2NTg1LCJpYXQiOjE3MDA3NTkzODUsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0OjgxMDAiLCJqdGkiOiIyOTIzMTE2My01ZjA0LTRkOTktYjY4MS1kYTU1ZTJkODQ4YzMiLCJzY29wZSI6Im9wZW5pZCBlbWFpbCBhdXRoc2VydmVyOnVzZXJpbmZvIiwic2lkIjoiNGU3YTlkYzYtYjFlMy00NGJmLTliNzktMWZhNTk0NjM2N2I5Iiwic3ViIjoiZTIwYzM5MzktY2E3My00MTJhLThmODgtMmYzMTAxYTZkZDRkIiwidHlwIjoiUmVmcmVzaCJ9.IT95tEihiGxNWhPNvu37w2l8DiDASjspgopERYDEIa-r9wvWHtrYZfwla0e_Cxx_GyK7_3CTfYVhw27wji0vIwMwFrCOv4SifopMnTpoeDEHlncmMQlMWglPA4JBOnXPmLXGmrGMbvhdnXNSQqxtnuamI_sHVGeBgibKlrQkmjVZ-G5tZz1_vjIbQL16-Eo9ZNF0ovKIHjiWpj3NA5Rb6q2h-h5fhIuk4aOwrZjJETPJv2czPV1fGEqgO1tdHwHzJjYIxV7evmZ3GXqmjbcGSvFMQM2WyHtcQBPAVy9ziylxwTDbfX1V619SJUns3-Yvt1eHe9thsit9AGsZGCCKCkj_XipQX7kyouPyLG7JXb4HNbrPvMPY8Gh7RuOMlhcrx4VPtLfJCeuPb3H_DVu1OgOHVeOQBrP_ZnCFOK4Pou1MsRfR9Ceja3dzJdsKb8-fpvhPpHtS_XOimwsF8w3rT53lN5nxI9-sy9Qai_8Bbbn2iAEFWd6sUsN6-m8YEc1-zsyJ7gOSJAYDhXfOnulGJ4HKwsAZZ7b3Q5lK1BsTBzcnbxdgszPUNnwufuDPydov85o0W6h_H8R2wpfvmZjqELmfg_dYdOVo-xw-9Px0J_Q8fDsqf2Q7H6E_jQ0eXzFabmLvxE2IpTg7Z4m2914AAt1LPlLTKVnkPl0Qoau0e4s",
    "refresh_expires_in": 7200,
    "scope": "openid email authserver:userinfo"
}
```

Decoded access token:

```javascript
{
    "acr": "urn:goiabada:pwd:otp_ifpossible",
    "amr": "pwd",
    "aud": "authserver",
    "auth_time": 1700759382,
    "exp": 1700759685,
    "iat": 1700759385,
    "iss": "https://localhost:8100",
    "jti": "78ec322f-4412-4731-893b-cae718ed7386",
    "nonce": "dPjdYJWSH6TgE14BTWPm9FC4La7tNqCkpmS7GVEx9lA",
    "scope": "openid email authserver:userinfo",
    "sid": "4e7a9dc6-b1e3-44bf-9b79-1fa5946367b9",
    "sub": "e20c3939-ca73-412a-8f88-2f3101a6dd4d",
    "typ": "Bearer"
}
```

Decoded id token:

```javascript
{
    "acr": "urn:goiabada:pwd:otp_ifpossible",
    "amr": "pwd",
    "aud": "test-client-1",
    "auth_time": 1700759382,
    "email": "someone@example.com",
    "email_verified": false,
    "exp": 1700759685,
    "iat": 1700759385,
    "iss": "https://localhost:8100",
    "jti": "3646c2f6-ba0c-4e87-800d-90fbcb49e2bd",
    "nonce": "dPjdYJWSH6TgE14BTWPm9FC4La7tNqCkpmS7GVEx9lA",
    "sid": "4e7a9dc6-b1e3-44bf-9b79-1fa5946367b9",
    "sub": "e20c3939-ca73-412a-8f88-2f3101a6dd4d",
    "typ": "ID"
}
```

Decoded refresh token:

```javascript
{
    "aud": "https://localhost:8100",
    "exp": 1700766585,
    "iat": 1700759385,
    "iss": "https://localhost:8100",
    "jti": "29231163-5f04-4d99-b681-da55e2d848c3",
    "scope": "openid email authserver:userinfo",
    "sid": "4e7a9dc6-b1e3-44bf-9b79-1fa5946367b9",
    "sub": "e20c3939-ca73-412a-8f88-2f3101a6dd4d",
    "typ": "Refresh"
}
```

Note: This is solely for the purpose of illustrating the overall flow. In an actual real-world integration, there are important security verifications that must be made.

The preceding example specifically sought OpenID Connect claims, addressing an authentication use case wherein the client application retrieves the user's email information upon authentication.

Now, consider a scenario where the user seeks access to a resource named Reports API and requests permission to view a report.

In this context, the initial step is to confirm the existence of both the specified resource and the corresponding permission in the administrative area of Goiabada. Then, the process involves granting the identified permission to the user.

![Screenshot](img/examples1.png)

Finally, we can execute the authorization code flow with PKCE, requesting that permission in the `scope` parameter.

```
https://localhost:8100/auth/authorize?
client_id=test-client-1&
code_challenge=Cm0QcqGfaznJVJPU5YZNOiJqwDtmurxwRhey2xNSvF4&
code_challenge_method=S256&
redirect_uri=https%3A%2F%2Fgoiabada-test-client%3A8090%2Fcallback.html&
response_type=code&
response_mode=query&
state=IiXcAd4ib7oCu11DFPWM5n8wXPhgE73sofAUJiwfkXk&
nonce=4EdIRqT461t--kYfZobc99L-I_JzehBeCcB9vCL1iHo&
scope=openid+email+reports-api%3Aread-report
```

The resultant token will contain the requested permission if it has been granted to the user or if the user is a member of a group that has been assigned the permission.

```javascript
{
    "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVlYjlmZDk4LWIzOWQtNDBiMC04NGVhLWFhMjc0ZWY3M2VkMyIsInR5cCI6IkpXVCJ9.eyJhY3IiOiJ1cm46Z29pYWJhZGE6cHdkOm90cF9pZnBvc3NpYmxlIiwiYW1yIjoicHdkIiwiYXVkIjpbImF1dGhzZXJ2ZXIiLCJyZXBvcnRzLWFwaSJdLCJhdXRoX3RpbWUiOjE3MDA3NjA3NzAsImV4cCI6MTcwMDc2MTA3MiwiaWF0IjoxNzAwNzYwNzcyLCJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo4MTAwIiwianRpIjoiY2Y4OWI5MWYtZWJkYi00YzBkLWIxNGYtOGY5MzgwNjdkNmU0Iiwibm9uY2UiOiI0RWRJUnFUNDYxdC0ta1lmWm9iYzk5TC1JX0p6ZWhCZUNjQjl2Q0wxaUhvIiwic2NvcGUiOiJvcGVuaWQgZW1haWwgcmVwb3J0cy1hcGk6cmVhZC1yZXBvcnQgYXV0aHNlcnZlcjp1c2VyaW5mbyIsInNpZCI6IjRlN2E5ZGM2LWIxZTMtNDRiZi05Yjc5LTFmYTU5NDYzNjdiOSIsInN1YiI6ImUyMGMzOTM5LWNhNzMtNDEyYS04Zjg4LTJmMzEwMWE2ZGQ0ZCIsInR5cCI6IkJlYXJlciJ9.VxpRUzQC43RZugjIv0IObCC5j2qXd76z3n4cxOPS_EjcSpIElFZkLgzcvkt6667MFTlFFCSb5EooTgd93JdGSJ7bL_LLlGvlkyp2jY0pjwfJZhcHPlLp248e-aTakuOoKO1eYWa6EnpFMt6yXBvI0vhn2khhVtZkIGPsDq_957stWgR9ik-ZLBi6xiE7eGHfkdWJlzTUlo5i81onCgN0Uec9pHNM-hAz80kszv9j-Ej-nW93Ie3ciKjWfbMmKXRd17T3l5P-Xsi0m_4W8JkRioRPsg5SysXtSxElj2U1z2AZZPAlxXaRdHOpEjp0ri8cTVY__o7TGjEIZKpqWgkfsW6aNV5i104WdEdt3K5OerJbMhSoBPhEb58nQAOheEBXe23cTq8U2aXbpTgpZSVPpDKql_qqVCFYq0HKGbWeWokPGEwLAyz2pnwbkUptGAS5J5EfEv6SBF8UdYSY7s3_bGqk8gnx-FiO37HiDYcYYFoS6gfHXVdKUZX4miheBNUdXRNFC9f702nnoHFqdFGJYbx81po1wDMIU_3yF3nWd5icJr1kUlbmlxxBkua1GFTZ382vZ6Ov3pPiB2UToUVlQm07T1XuRN12yyLJHSsDwwWwEgOfPHFTBrt3rSbkBm9t3agM3ZWyZJ45qgR6Z-zSmcE1dUqiBR1RJcu3Djvma58",
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVlYjlmZDk4LWIzOWQtNDBiMC04NGVhLWFhMjc0ZWY3M2VkMyIsInR5cCI6IkpXVCJ9.eyJhY3IiOiJ1cm46Z29pYWJhZGE6cHdkOm90cF9pZnBvc3NpYmxlIiwiYW1yIjoicHdkIiwiYXVkIjoidGVzdC1jbGllbnQtMSIsImF1dGhfdGltZSI6MTcwMDc2MDc3MCwiZW1haWwiOiJzb21lb25lQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJleHAiOjE3MDA3NjEwNzIsImlhdCI6MTcwMDc2MDc3MiwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODEwMCIsImp0aSI6IjY1MjEwMTJjLTI3OTUtNGU0NC05NDY2LTViOTI2YWY1OTBlOSIsIm5vbmNlIjoiNEVkSVJxVDQ2MXQtLWtZZlpvYmM5OUwtSV9KemVoQmVDY0I5dkNMMWlIbyIsInNpZCI6IjRlN2E5ZGM2LWIxZTMtNDRiZi05Yjc5LTFmYTU5NDYzNjdiOSIsInN1YiI6ImUyMGMzOTM5LWNhNzMtNDEyYS04Zjg4LTJmMzEwMWE2ZGQ0ZCIsInR5cCI6IklEIn0.S6sdkpdCEuAdhRHSCLasxVCavDgepzSnT1i51ro-tH6GUq5FVJF8WMt-HbC8i69_P6rbfSIjO34OW-VQ3p2d7N8GWsefmipZDbaZWe9Szb47oP3RR30rYWHxnEhyr3bF06-C0_uNSKWdd28rIaHDVD95NDiZHzOKX-QJIypIxsDUs9LUsw-mWVRljOfGjx3OgLR4NmT9bQdDcVMb5Us9wnriIUrWchjNAkXJO8U7IDOL2y3zpXeky4bpDLbGhO7hboirOVP0gPMVGAqCYhA5sgE9MfPDye5zCVpE4uk44SOKMiVcIs5JmJIZatwMxa2bX2AdHEkGkN21fO-l_z3YrEqrl2CvdCO-hZX9ZwOBIEplZtsOywWCZB16EO1NP2Ty-XEUCr4TLhGoWOPdRRasIbPx2wLghyiHPC51FVzMEwvOBmwGH5oxlwPaGpTNkyo9py92c9Owc7-4NJPVOoY41Da8dE4rB6FunwdgZL69w_rvCMYpwk53koJJeVaY2T6ilvwLf3RSbBikFpHcxLPaUuWraJeQ0YY2C8Rrj1LzQ9gWgP3zmBEShLeYXMFqJBfoQ_owX052Z0wruwUltN55GGK8zDdK6EMj1avIX8evnIRGKj44jtehtMZxfEgjSrji7Vpuk4q8J_fGPMsxuEPSsYREmfruXscyyz_Qd6PfX3o",
    "token_type": "bearer",
    "expires_in": 300,
    "refresh_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVlYjlmZDk4LWIzOWQtNDBiMC04NGVhLWFhMjc0ZWY3M2VkMyIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo4MTAwIiwiZXhwIjoxNzAwNzY3OTcyLCJpYXQiOjE3MDA3NjA3NzIsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0OjgxMDAiLCJqdGkiOiIyNzVhMmYzNS0wYjIzLTQwYjktYmIwNy0yYTU2OTgwYzZmZGQiLCJzY29wZSI6Im9wZW5pZCBlbWFpbCByZXBvcnRzLWFwaTpyZWFkLXJlcG9ydCBhdXRoc2VydmVyOnVzZXJpbmZvIiwic2lkIjoiNGU3YTlkYzYtYjFlMy00NGJmLTliNzktMWZhNTk0NjM2N2I5Iiwic3ViIjoiZTIwYzM5MzktY2E3My00MTJhLThmODgtMmYzMTAxYTZkZDRkIiwidHlwIjoiUmVmcmVzaCJ9.W-h0wLCFmXi54pqN5gWSlQD8PSi5TJIecjQNS0ZPf8G0tgkQi1bY9qvOe8khlmox3vt8jbe5GH9i26-GLIJVl5DSQ3F_Y6hIo3EdyYPW_4MmBwvr3ZOafPl98epp8lwtnOjeVeA9RsmLe00OzNTJYYFpcuGqjijiyHcOb-6oKkIkBhG_MtI08_Q7BKsnaKK86mBmsvowoT7zK4LFSGQ0gBeg9WgSJyhzYVhsvdISUXJDrOEIwRFvpAosdBjtwzgVCmqLV0ziMKbFwq9AZTHcmmI5mFPB_TkmryeYaQd1Nw3rXP3v9YmtATxa_EsoCwEpqtP-LrGC3w9olrqroyXsSaqyP_9wnACLOjiBOlmPtKweAECuF3fKvLgEsR26-KagWKmIhKLAobHTj3FTgXeZiAqoNQgUZ0SgOHyOnpbjNS6VOIpdbOhybUiZfr7sIGQIBsCpG1GpAXCchKxdQ6uUQhe-yNcCLn4TU14qOwgxwf0pxok5Y6HhstSwJUbqpLX1IA8VycQNJPZD3KnjJ5RWR7MyQ2yExnO8U2hv-ME31h_QnnRkRTomC9L5xeguO9kYNmFiJBqSkkT_3V4DVQ4uUorBbwjBZYH9Vt7-6pTQUj756oktih3tcy6nT9TVqR7LcS07oQlbnpWHTV-nwkU63ym_lmrss9uW32viHp0eFrk",
    "refresh_expires_in": 7200,
    "scope": "openid email reports-api:read-report authserver:userinfo"
}
```

Decoded access token:

```javascript
{
    "acr": "urn:goiabada:pwd:otp_ifpossible",
    "amr": "pwd",
    "aud": [
            "authserver",
            "reports-api"
    ],
    "auth_time": 1700760770,
    "exp": 1700761072,
    "iat": 1700760772,
    "iss": "https://localhost:8100",
    "jti": "cf89b91f-ebdb-4c0d-b14f-8f938067d6e4",
    "nonce": "4EdIRqT461t--kYfZobc99L-I_JzehBeCcB9vCL1iHo",
    "scope": "openid email reports-api:read-report authserver:userinfo",
    "sid": "4e7a9dc6-b1e3-44bf-9b79-1fa5946367b9",
    "sub": "e20c3939-ca73-412a-8f88-2f3101a6dd4d",
    "typ": "Bearer"
}
```

If the permission is not granted to the user, it won't be included in the resulting access token and response.