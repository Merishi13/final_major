/* eslint-disable no-undef */
import React from "react";
import PropTypes from "prop-types";

export default function Footer(props) {
  return (
    <div>
      <footer style={{ background: "black" }}>
        <div className="card" style={{ background: "black" }}>
          <div className="card-header" style={{ color: "white" }}>
            <img
              src="/Jeevanlogo1.jpeg"
              alt="Bootstrap"
              width="75"
              height="75"
              //   padding="5 px"
            />
            {props.footer}
          </div>
          <div className="card-body" style={{ color: "white" }}>
            <h5 className="card-title">What is our Mission?</h5>
            <p className="card-text">
              We created the application to make sure the process in the medical
              field is faster, more efficient, costs less and can save more
              lives than it already is. This application was created so that as
              many processes as possible could be made easier. It was inspired
              by the rapid inflation of rates in the medical industry and to
              reduce whatever costs possible.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

Footer.propTypes = { footer: PropTypes.string };
