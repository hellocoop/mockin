
const users = [
    {
        "sub": "00000000-0000-0000-0000-00000000",
        "name": "John Smith",
        "nickname": "Jack",
        "given_name": "John",
        "family_name": "Smith",
        "picture": "https://pictures.hello.coop/mock/portrait-of-john-smith.jpeg",
        "email": "john.smith@example.com",
        "phone": "+19875550123",
        "ethereum": "0x0000000000000000000000000000000000000000",
        "discord": {
            "username": "jackjack",
            "id": "0000000000"
        },
        "github": {
            "username": "johnsmith",
            "id": "000000000"
        },
        "gitlab": {
            "username": "johnsmith",
            "id": "00000000"
        },
        "twitter": {
            "username": "JohnSmith",
            "id": "0000000"
        }
    },
    {
        "sub": "11111111-1111-1111-1111-11111111",
        "name": "Зо́я-Алёна Николаевна Смирно́вa-Đặng Thị Hồng Ân",
        "nickname": "Зо́я-Алёна",
        "given_name": "Смирно́вa-Đặng Thị Hồng Ân",
        "family_name": "Николаевна Smirnova-Dang",
        "picture": "https://pictures.hello.coop/mock/1111.jpeg",
        "email": "Zoya-Alyona@xn--bcher-kva.example.com",
        "phone": "+84912345678",
        "ethereum": "0x1111111111111111111111111111111111111111",
        "discord": {
            "username": "Zoya-Alyona",
            "id": "1111111111"
        },
        "github": {
            "username": "zoya-alyona",
            "id": "111111111"
        },
        "gitlab": {
            "username": "zoya-alyona",
            "id": "11111111"
        },
        "twitter": {
            "username": "Zoya-Alyona",
            "id": "1111111"
        }
    },
    {
        "sub": "22222222-2222-2222-2222-22222222",
        "name": "AlexanderJonathan MaximillianTheodore SebastianArchibaldMontgomeryRutherfordBeauregardFitzwilliamPercivalWolfgangZachariahBartholomewOctaviusLysanderDemetriusNathanielHumphreyWellington",
        "nickname": "AlexanderJonathanMaximillian",
        "given_name": "AlexanderJonathan MaximillianTheodore",
        "family_name": "SebastianArchibaldMontgomeryRutherfordBeauregardFitzwilliamPercivalWolfgangZachariahBartholomewOctaviusLysanderDemetriusNathanielHumphreyWellington",
        "picture": "https://pictures.hello.coop/mock/2222.jpeg",
        // 254 chars
        "email": "AlexanderJonathanMaximillianTheodoreSebastianArchibaldMontgomery@RutherfordBeauregardFitzwilliamPercivalWolfgangZachariahBartholomewOctaviusLysanderDemetriusNathanielHumphreyWellington.123456789.123456789.123456789.123456789.123456789.1234567.example.com",
        "phone": "+222222222222222",
        "ethereum": "0x2222222222222222222222222222222222222222",
        "discord": { // 32 chars
            "username": "AlexanderJonathanMaximillianTheo",
            "id": "2222222222"
        },
        "github": { // 39 chars
            "username": "AlexanderJonathanMaximillianTheodoreSeb",
            "id": "222222222"
        },
        "gitlab": { // 32 chars
            "username": "AlexanderJonathanMaximillianTheo",
            "id": "22222222"
        },
        "twitter": { // 15 chars
            "username": "AlexanderJohnny",
            "id": "2222222"
        }
    },
    {
        "sub": "sub_PrHrJvaaszcdyltTt52v3UcH_dbf",
        "name": "Lewis Carroll",
        "nickname": "Lewis",
        "given_name": "Lewis",
        "family_name": "Carroll",
        "picture": "https://pictures.hello.coop/mock/john-smith-yahoo.jpeg",
        "email": "lewis.carroll@example.org",
        "phone": "+31913726352",
        "ethereum": "0x1230000000000000000000000000000000000000",
        "discord": {
            "username": "lewiscarroll",
            "id": "0000000000"
        },
        "github": {
            "username": "lewiscarroll",
            "id": "000000000"
        },
        "gitlab": {
            "username": "lewiscarroll",
            "id": "00000000"
        },
        "twitter": {
            "username": "lewiscarroll",
            "id": "0000000"
        }
    },
    {
        "sub": "sub_wdfp66OC0Me43YW9q6sisnP6_h2q",
        "name": "Dan Brown",
        "nickname": "Dan",
        "given_name": "Dan",
        "family_name": "Brown",
        "picture": "https://pictures.hello.coop/mock/john-smith-facebook.jpeg",
        "email": "dan.brown@example.net",
        "phone": "+919928393823",
        "ethereum": "0x3240000000000000000000000000000000000000",
        "discord": {
            "username": "danbrown",
            "id": "0000000000"
        },
        "github": {
            "username": "danbrown",
            "id": "000000000"
        },
        "gitlab": {
            "username": "danbrown",
            "id": "00000000"
        },
        "twitter": {
            "username": "danbrown",
            "id": "0000000"
        }
    }
]

const loginHints = {}, domainHints = {};
const ignoreSubsForDomainHint = [
    '22222222-2222-2222-2222-22222222' // insanely lengthy domain
]

for (const user of users) {
    // set login hint
    if (user.sub && user.sub.startsWith('sub_'))
        loginHints[user.sub] = user
    if (user.email)
        loginHints[user.email] = user

    // set domain hint
    if(!ignoreSubsForDomainHint.includes(user.sub) && user.email) {
        const domain = user.email.split('@')[1]
        if (domain)
            domainHints[domain] = user
    }
}

export default users[0]
export { users, loginHints, domainHints }