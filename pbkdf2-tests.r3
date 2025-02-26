REBOL [
    title: "pbkdf2 test script"
    needs: 3.11.0
]

import %pbkdf2.reb

cases-sha1: [
    [
        password "password" 
        salt "salt" 
        iterations 1 
        keylength 20 
        output #{0C60C80F961F0E71F3A9B524AF6012062FE037A6} 
        ]
    [
        password "password" 
        salt "salt" 
        iterations 2 
        keylength 20 
        output #{EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957}
        ]
    [
        password "password" 
        salt "salt" 
        iterations 4096 
        keylength 20 
        output #{4B007901B765489ABEAD49D926F721D065A429C1}
        ]
    [
        password "passwordPASSWORDpassword" 
        salt "saltSALTsaltSALTsaltSALTsaltSALTsalt" 
        iterations 4096 
        keylength 25 
        output #{3D2EEC4FE41C849B80C8D83662C0E44A8B291A964CF2F07038}
        ] 
    [
        password "pass^@word" 
        salt "sa^@lt" 
        iterations 4096 
        keylength 16 
        output #{56FA6AA75548099DCC37D7F03425E0C3}
        ]            
    [
        password "BBašq+'41+'41+'op123lfsdkfo131o2k" 
        salt "1'20341opfsdkf'130e4o1+'24'1+olopdkf23'0r23r21" 
        iterations 5000
        keylength 55
        output #{53716E90150130C290F5DD985230BED3A484DA7385E74C15667B11AE383E41F7AF52155CF392D552CF5DBBD989D4D3A75C1A08DB6D0453}
        ]            
    [
        password "BBašq+'41+'41+'op123lfsdkfo131o2k" 
        salt "1'20341opfsdkf'130e4o1+'24'1+olopdkf23'0r23r21" 
        iterations 7000
        keylength 100
        output #{856DC7F1741EF633A579F46056ADE919768EFC9F4E38988C8DD366A5D4FABED610D97D0416DD1DDD2D8C1E2741168DCEA4C1134FC243B30654C17D48C54EE1D1C57BA59877605002A3FDAF2FB3090B739F2A801AEC2EFA8EC7BD533E0AEBA56BB5C92DC7}
        ]            
]

foreach test cases-sha1 [
    print-horizontal-line
    ?? test
    result: pbkdf2 test/password test/salt test/iterations test/keylength 'sha1
    ? result
    print either/only test/output = result [
        as-yellow "OK"
    ][  as-red    "FAILED"]
]