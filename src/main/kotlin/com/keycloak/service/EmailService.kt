package com.keycloak.service

import org.springframework.mail.javamail.JavaMailSender
import org.springframework.mail.javamail.MimeMessageHelper
import org.springframework.stereotype.Service

@Service
class EmailService(
    private val javaMailSender: JavaMailSender
) {
    fun sendEmail(to: String, subject: String, body: String) {
        val message = javaMailSender.createMimeMessage()
        val helper = MimeMessageHelper(message, true, "UTF-8")

        helper.setFrom("no-reply@example.com") // Replace with your email address
        helper.setTo(to)
        helper.setSubject(subject)
        helper.setText(body, true)

        // Send the email
        javaMailSender.send(message)
    }
}
