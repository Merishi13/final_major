/* eslint-disable no-undef */
import React, { useEffect } from "react";
export default function HospitalHome({
  setShowNavbar,
  setHosbar,
  setPatientbar,
}) {
  useEffect(() => {
    // After redirecting to /Hoshome, change showNavbar to true
    setShowNavbar(true);
    setHosbar(true);
    setPatientbar(false);
    const apiUrl = "http://127.0.0.1:5000/api/redirecth";
    fetch(apiUrl, {
      method: "GET", // Use the appropriate HTTP method (POST, GET, etc.)
      headers: {
        "Content-Type": "application/json",
      },
      // body: JSON.stringify(requestBody),
    })
    .then((response) => {
      if (!response.ok) {
        throw new Error("Network response was not ok");
      }
      return response.json();
    })
    .then((data) => {
      // Handle the API response data as needed
      // For example, you can check if the login was successful
      console.log(data);
      if (data.redirect) {
        // Redirect to the dashboard page on successful login
        if (data.redirect === "true") {
          
          navigate("/");
        }
      }
    })
  }, []);
  return (
    <div>
      <section class="about_section">
        <div class="container">
          <div class="row">
            <div class="col-md-6">
              <div class="img-box">
                <img src="about-img.jpg" alt="" />
              </div>
            </div>
            <div class="col-md-6">
              <div class="detail-box">
                <div class="heading_container">
                  <h2>
                    Jeevan <span>Hospital Records</span>
                  </h2>
                </div>
                <p>
                  This service will help the patient know their records and
                  hospitals access the records so that everyon can avoid the
                  unnecessary tests required by all the hospitals and skip to
                  treating the patient. This will also help the patients to be
                  up to date witn their medical health.
                </p>
                <a href="/"> Read More </a>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
