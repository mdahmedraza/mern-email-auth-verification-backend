const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const {generateToken, hashToken} = require("../utils");
var parser = require("ua-parser-js");
const jwt = require("jsonwebtoken");
const sendEmail = require("../utils/sendEmail");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const Cryptr = require("cryptr");
const {OAuth2Client} = require("google-auth-library");

const cryptr = new Cryptr(process.env.CRYPTR_KEY);

// const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// register user
const registerUser = asyncHandler(async (req, res) => {
    const {name, email, password} = req.body;

    // validation
    if(!name || !email || !password){
        res.status(400);
        throw new Error("please fill in all the required fields.");
    }
    if(password.length < 6){
        res.status(400);
        throw new Error("password must be up to 6 characters.");
    }

    // check if user exists
    const userExists = await User.findOne({email});

    if(userExists) {
        res.status(400);
        throw new Error("email already in use.");
    }

    // get user agent
    const ua = parser(req.headers["user-agent"]);
    const userAgent = [ua.ua];

    // create new user
    const user = await User.create({
        name,
        email,
        password,
        userAgent,
    })

    // generate token
    const token = generateToken(user._id);

    // send HTTP-only cookie
    res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day
        sameSite: "none",
        secure: true,
    })
    if(user){
        const {_id, name, email, phone, bio, photo, role, isVerified} = user;

        res.status(201).json({
            _id, name, email, phone, bio, photo, role, isVerified, token
        })
    } else {
        res.status(400);
        throw new Error("invalid user data")
    }
})

// login user;
const loginUser = asyncHandler(async (req, res) => {
    const {email, password} = req.body;

    // validation
    if(!email || !password){
        res.status(400);
        throw new Error("please add email and password");
    }

    const user = await User.findOne({email});

    if(!user){
        res.status(404);
        throw new Error("user not found, please signup");
    }

    const passwordIsCorrect = await bcrypt.compare(password, user.password);

    if(!passwordIsCorrect) {
        res.status(400);
        throw new Error("invalid email or password");
    }

    // trgger 2FA for unknown user agent

    const ua = parser(req.headers["user-agent"]);
    const thisUserAgent = ua.ua;
    console.log(thisUserAgent);
    const allowedAgent = user.userAgent.includes(thisUserAgent);

    if(!allowedAgent) {
        // generate 6 digit code
        const loginCode = Math.floor(100000 + Math.random() * 900000);
        console.log(loginCode)

        // encrypt login code before saving to db
        const encryptedLoginCode = cryptr.encrypt(loginCode.toString());

        // delete token if it exists in db
        let userToken= await TokenExpiredError.findOne({userId: user._id});
        if(userToken) {
            await userToken.deleteOne();
        }

        // save token to db
        await new jwt.TokenExpiredError({
            userId: user._id,
            lToken: encryptedLoginCode,
            createdAt: Date.now(),
            expiresAt: Date.now() + 60 * (60 * 1000), // 60 mins
        }).save();

        res.status(400);
        throw new Error("new browser or device detected");
    }

    // generate token
    const token = generateToken(user._id);
    if(user && passwordIsCorrect) {
        // send http-only cookie
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 day
            // sameSite: "none",
            // secure: true
        })

        const {_id, name, email, phone, bio, photo, role, isVerified} = user;
        
        res.status(200).json({
            _id, name, email, phone, bio, photo, role, isVerified, token
        })
    } else {
        res.status(500);
        throw new Error("something went wrong, please try again");
    }
})

// send login code...not understand
const sendLoginCode = asyncHandler(async(req, res) => {
    const {email} = req.params;
    const user = await User.findOne({email});

    if(!user) {
        res.status(404);
        throw new Error("user not found");
    }

    // find login code in db
    let userToken = await Token.findOne({
        userId: user._id,
        expiresAt: {$gt: Date.now()},
    })

    if(!userToken) {
        res.status(404);
        throw new Error("invalid or expired token, please login again");
    }


    const loginCode = userToken.lToken;
    const decryptedLoginCode = cryptr.decrypt(loginCode);

    //send login code
    const subject = "Login Access Code - AUTH:Z";
    const send_to = email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = "ahamedraza2244@gmail.com";
    const template = "loginCode";
    const name = user.name;
    const link = decryptedLoginCode;

    try{
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link
        );
        res.status(200).json({message: `access code sent to ${email}`});
    } catch (error) {
        res.status(500);
        throw new Error("email not sent, please try again");
    }
})

// login with code--- note understand.....
const loginWithCode = asyncHandler(async(req, res) => {
    const {email} = req.params;
    const {loginCode} = req.body;
    
    const user = await User.findOne({email});
    
    if(!user) {
        res.status(404);
        throw new Error("user not found");
    }

    // find user login token
    const userToken = await Token.findOne({
        userId: user.id,
        expiresAt: {$gt: Date.now()},
    });

    if(!userToken) {
        res.status(404);
        throw new Error("invalid or expired token, please login again");
    }
    const decryptedLoginCode = cryptr.decrypt(userToken.lToken);

    if(loginCode !== decryptedLoginCode) {
        res.status(400);
        throw new Error("incorrect login code, please try again")
    } else {
        // register user agent
        const ua = parser(req.headers["user-agent"]);
        const thisUserAgent = ua.ua;
        user.userAgent.push(thisUserAgent);
        await user.save();

        // generate token
        const token = generateToken(user._id);

        // send http-onky cookie
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 day
            sameSite: "none",
            secures: true
        });
        const {_id, name, email, phone, bio, photo, role, isVerified} = user;

        res.status(200).json({
            _id,
            name,
            email,
            phone,
            bio,
            photo,
            role,
            isVerified,
            token
        })
    }
    
})

// send vefification email...we can reset password using 'resetToken' which is in console 
// but email not sent i thing becuase in this should another 3rd party for email...
const sendVerificationEmail = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);
    
    if (!user) {
        res.status(404);
        throw new Error("User not found");
    }

    if (user.isVerified) {
        res.status(400);
        throw new Error("User already verified");
    }

    // delete token if it exists in db
    let token = await Token.findOne({ userId: user._id });
    if (token) {
        await token.deleteOne();
    }

    // create verification token and save
    const verificationToken = crypto.randomBytes(32).toString("hex") + user._id;
    console.log(verificationToken);

    // hash token and save
    const hashedToken = hashToken(verificationToken);
    await new Token({
        userId: user._id,
        vToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60 * 1000), // 60 mins
    }).save();

    // construct verification URL
    const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;

    // send email
    const subject = "Verify Your Account - AUTH:Z";
    const send_to = user.email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = "ahamedraza2244@gmail.com";
    const template = "verifyEmail";
    const name = user.name;
    const link = verificationUrl;

    try {
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link
        );
        res.status(200).json({ message: "Verification email sent" });
    } catch (error) {
        console.error("Error occurred while sending verification email:", error);
        res.status(500).json({ error: "Email not sent, please try again" });
    }
});



// verify user
const verifyUser = asyncHandler(async(req, res) => {
    const {verificationToken} = req.params;

    const hashedToken = hashToken(verificationToken);

    const userToken = await Token.findOne({
        vToken: hashedToken,
        expiresAt: {$gt: Date.now()},
    });
    if(!userToken) {
        res.status(404);
        throw new Error("invalid or expired token");
    }

    // find user
    const user = await User.findOne({_id: userToken.userId});

    if(user.isVerified) {
        res.status(400);
        throw new Error("user is already verified")
    }

    // now verify user
    user.isVerified = true;
    await user.save();

    res.status(200).json({message: "account verification successful"})
})

// logout user
const logoutUser = asyncHandler(async(req, res) => {
    res.cookie("token", "", {
        path: "/",
        httpOnly: true,
        expires: new Date(0), // 1day
        sameSite: "none",
        secure: true,
    })
    return res.status(200).json({message: "lotout successful"})
})

// get user
const getUser = asyncHandler(async(req, res) => {
    const user = await User.findById(req.user._id);

    // if(user) {
    //     const {_id, name, email, phone, bio, photo, role, isVerified} = user;
    //     res.status(200).json({_id, name, email, phone, bio, photo, role, isVerified})
    // } else {
    //     res.status(404);
    //     throw new Error("user not found")
    // }
    if(user){
        res.status(200).json(user);
    }else{
        res.status(400);
        throw new Error("User Not Found");
    }
})

// update user
const updateUser = asyncHandler(async(req, res) => {
    const user = await User.findById(req.user._id);
    if(user) {
        const {name, email, phone, bio, photo, role, isVerified} = user;

        user.email = email;
        user.name = req.body.name || name;
        user.phone = req.body.phone || phone;
        user.bio = req.body.bio || bio;
        user.photo = req.body.photo || photo;
        
        const updatedUser = await user.save();

        res.status(200).json({
            _id: updatedUser._id,
            name: updatedUser.name,
            email: updatedUser.email,
            phone: updatedUser.phone,
            bio: updatedUser.bio,
            photo: updatedUser.photo,
            role: updatedUser.role,
            isVerified: updatedUser.isVerified
        });
    } else {
        res.status(404);
        throw new Error("user not found")
    }
});

// delete user

// const deleteUser = asyncHandler(async(req, res) => {
//     const user = await User.findByIdAndRemove(req.params.id);
//     if (!user) {
//         res.status(404);
//         throw new Error("User not found");
//     }
//     // await user.remove();
//     res.status(200).json({
//         message: "User deleted successfully"
//     });
// });

const deleteUser = asyncHandler(async(req, res) => {
    try{
        const {id} = req.params;
        await User.findByIdAndDelete(id);
        res.status(200).json({
            message: "user deleted successfully"
        })
    } catch (error) {
        res.status(404).json({message: "user not found"});
    }
})

// get users
const getUsers = asyncHandler(async (req, res) => {
    const users = await User.find().sort("-createdAt").select("-password");
    if(!users){
        res.status(500);
        throw new Error("something went wrong");
    }
    res.status(200).json(users)
})

// get login status
const loginStatus = asyncHandler(async (req, res) => {
    const token = req.cookies.token;
    if(!token) {
        return res.json(false);
    }
    // verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    if(verified) {
        return res.json(true);
    }
    return res.json(false);
})

// upgrade user
const upgradeUser = asyncHandler(async (req, res) => {
    const {role, id} = req.body;

    const user = await User.findById(id);

    if(!user) {
        res.status(404);
        throw new Error("user not found");
    }

    user.role = role;
    await user.save();

    res.status(200).json({
        message: `user role updated to ${role}`,
    })
})

// send automated emails -----we can reset password using 'resetToken' which is in console 
// but email not sent i thing becuase in this should another 3rd party for email...
const sendAutomatedEmail = asyncHandler(async (req, res) => {
    const {subject, send_to, reply_to, template, url} = req.body;

    if(!subject || !send_to || !reply_to || !template) {
        res.status(500);
        throw new Error("missing email parameter");
    }
    // get user
    const user = await User.findOne({email: send_to});
    if(!user) {
        res.status(404);
        throw new Error("user not found");
    }

    const sent_from = process.env.EMAIL_USER;
    const name = user.name;
    const link = `${process.env.FRONTEND_URL}${url}`;

    try{
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link
        );
        res.status(200).json({message: "email sent"});
    } catch (error) {
        res.status(500);
        throw new Error("email not sent, please try again");
    }
})

// forgot password...we can reset password using 'resetToken' which is in console 
// but email not sent i thing becuase in this should another 3rd party for email...
const forgotPassword = asyncHandler(async(req, res) => {
    const {email} = req.body;

    const user = await User.findOne({email});

    if(!user) {
        res.status(404);
        throw new Error("no user with this email");
    }
    
    // delete token if it exists in db
    let token = await Token.findOne({userId: user._id});
    if(token) {
        await token.deleteOne();
    }

    // create verification token and save
    const resetToken = crypto.randomBytes(32).toString("hex") + user._id;
    console.log(resetToken);

    // hash token and save
    const hashedToken = hashToken(resetToken);
    await new Token({
        userId: user._id,
        rToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60 * 1000), // 60 mins
    }).save();

    // construct reset url
    const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

    // send email
    const subject = 'password reset request - AUTH:Z';
    const send_to = user.email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = "ahamedraza2233@outlook.com";
    const template = "forgotPassword";
    const name = user.name;
    const link = resetUrl;

    try{
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link
        );
        res.status(200).json({message: "password reset email sent"});
    } catch (error) {
        res.status(500);
        throw new Error("email not sent, please try again");
    }
});

// reset password
const resetPassword = asyncHandler(async(req, res) => {
    const {resetToken} = req.params;
    const {password} = req.body;
    console.log(resetToken);
    console.log(password);

    const hashedToken = hashToken(resetToken);

    const userToken = await Token.findOne({
        rToken: hashedToken,
        expiresAt: {$gt: Date.now()},
    });
    if(!userToken) {
        res.status(404);
        throw new Error("invalid or expired token");
    }

    // find user
    const user = await User.findOne({_id: userToken.userId});
    // now reset password
    user.password = password;
    await user.save();

    res.status(200).json({message: "password reset successful, please login"})
})

// change password
const changePassword = asyncHandler(async(req, res) => {
    const {oldPassword, password} = req.body;
    const user = await User.findById(req.user._id);

    if(!user) {
        res.status(404);
        throw new Error("user not found");
    }
    if(!oldPassword || !password) {
        res.status(400);
        throw new Error("please enter old and new password")
    }

    // check if old password is correct
    const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

    // save new password
    if(user && passwordIsCorrect) {
        user.password = password;
        await user.save();
        res
            .status(200)
            .json({message: "password change successful, please re-login"});
    } else {
        res.status(400);
        throw new Error("old password is incorrect");
    }
})

// login with google
// codes are not written

module.exports = {
    registerUser,
    loginUser,
    sendLoginCode,
    loginWithCode,
    sendVerificationEmail,
    verifyUser,
    logoutUser,
    getUser,
    updateUser,
    deleteUser,
    getUsers,
    loginStatus,
    upgradeUser,
    sendAutomatedEmail,
    forgotPassword,
    resetPassword,
    changePassword,
}
