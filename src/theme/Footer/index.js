import React, { useEffect } from "react"
import Footer from "@theme-original/Footer"
import { useLocation } from "@docusaurus/router"

export default function FooterWrapper(props) {
    let { pathname } = useLocation()

    useEffect(() => {
        const cookieValue = document.cookie
            .split("; ")
            .find((row) => row.startsWith("username="))
            ?.split("=")[1]

        const username = cookieValue ? decodeURIComponent(cookieValue) : ""
        console.log("Username:", username)

        if (username !== "") {
            document.querySelector(".username").textContent = username
            document.querySelector(".username").style.fontWeight = "var(--ifm-font-weight-semibold)"
            document.querySelector(".logout").style.display = "block"
        } else {
            document.querySelector(".login").style.display = "block"
        }
        // document.querySelector(".navbar__inner").style.display = "flex"
        // // Check if on landing page
        // setIsDocsPage(true)
        // document.querySelector(".request-demo-button").style.display = "none"
        // document.querySelectorAll(".hide-on-docs").forEach((el) => (el.style.display = "none"))
        // document.querySelector(".navbar__inner").style.display = "flex"
        // document.querySelector(".navbar__inner").style.maxWidth = "none"
        // document.querySelectorAll(".hide-on-landing").forEach((el) => (el.style.display = "none"))
    }, [])

    return (
        <>
            <Footer {...props} />
        </>
    )
}
