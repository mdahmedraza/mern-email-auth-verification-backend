const nodemailer = require("nodemailer");
const hbs = require("nodemailer-express-handlebars");
const path = require("path");

const sendEmail = async (
    subject,
    send_to,
    sent_from,
    reply_to,
    template,
    name,
    link
) => {
    // create email transporter
    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: 587,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
        tls: {
            rejectUnauthorized: false,
        }
    })

    const handlerOptions = {
        viewEngine: {
            extName: '.handlebars',
            partialsDir: path.resolve("./views"),
            defaultLayout: false,
        },
        viewPath: path.resolve("./views"),
        extName: ".handlebars"
    };
    transporter.use("compile", hbs(handlerOptions));

    // options for sending email
    const options = {
        from: sent_from,
        to: send_to,
        replyTo: reply_to,
        subject,
        template,
        context: {
            name,
            link
        }
    }

    // send email
    transporter.sendMail(options, function (err, info) {
        if(err) {
            console.log(err);
        } else {
            console.log(info);
        }
    })
}

module.exports = sendEmail;