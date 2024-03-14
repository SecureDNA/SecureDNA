/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { faWarning } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { download, makeFileName } from "@securedna/frontend_common";
import {
  FieldArray,
  FieldArrayRenderProps,
  Form,
  Formik,
  FormikErrors,
  FormikProps,
} from "formik";
import { useState } from "react";
import {
  Button,
  ExemptionTable,
  FormInput,
  FormPhoneInput,
  PrimaryButton,
  ShippingAddresses,
} from "src/components";
import { AuthenticatorsInput } from "src/components/AuthInput";
import { Page } from "src/components/Page";
import {
  ExemptionListFormData,
  OrganismWithSource,
  ShippingAddress,
  emptyExemptionListFormData,
} from "src/types";
import { isOrcidChecksumValid } from "src/util/orcid";
import { makeEltrPem } from "src/util/sign_eltr";

const emailRegex =
  /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i;

const orcidRegex = /^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$/;

const yubikeyOtpRegex = /^[cbdefghijklnrtuv]{44}$/;

const ExemptionRequestForm = () => {
  const [page, setPage] = useState(0);
  const introPageIndex = 0;
  const shippingPageIndex = 1;
  const exemptionsPageIndex = 2;
  const successPageIndex = 3;

  const renderIntroPage = (props: FormikProps<ExemptionListFormData>) => (
    <>
      <div className="max-w-prose mx-auto">
        <p>
          This application helps you request a token that exempts you from
          synthesis bans on controlled organisms. Here's how it works:
        </p>
        <ol className="list-decimal ml-8 my-4 space-y-4">
          <li>
            Fill out information about <b>who you are</b> and where the DNA will
            be shipped. This information is embedded in your token, and prevents
            it from being used by others.
          </li>
          <li>
            Specify the <b>controlled organisms</b> you need to be able to
            synthesize. You can specify GenBank accession numbers or full FASTA
            sequences.
          </li>
          <li>
            Download the resulting <b>token request file</b> and send it to your
            superior or biosafety officer. They will verify your request and
            send you a token.
          </li>
        </ol>
      </div>
    </>
  );

  const renderShippingPage = (props: FormikProps<ExemptionListFormData>) => (
    <>
      <h2>Shipping Addresses</h2>
      <div className="rounded-lg bg-black/5 my-2 py-4 px-6 max-w-prose self-center">
        <b>Warning:</b> The token will be limited to the provided shipping
        addresses. The addresses can't be changed later.
      </div>
      <FieldArray
        name="shippingAddresses"
        render={(arrayHelpers: FieldArrayRenderProps) => (
          <ShippingAddresses
            arrayHelpers={arrayHelpers}
            shippingAddresses={props.values.shippingAddresses}
          />
        )}
      />
      <h2>Contact Info</h2>
      <div className="rounded-lg bg-black/5 p-4">
        <FormInput
          required={true}
          label="E-mail address"
          type="email"
          name="requestor.email"
        />
        <FormInput label="Contact's full name" name="requestor.name" />
        <FormPhoneInput label="Phone number" name="requestor.phone_number" />
        <FormInput
          label="ORCID iD"
          name="requestor.orcid"
          placeholder="0000-0000-0000-0000"
          digitPattern={{
            pattern: "0000-0000-0000-0000",
            digitRegex: /[0-9X]/gi,
            transform: "uppercase",
          }}
        />
      </div>
      <h2>Two-factor authentication</h2>
      <p className="mb-2">
        An OTP from one of the provided devices will be required to use the
        resulting token.
      </p>
      <p className="mb-2 py-4 px-6 bg-black/5 rounded-lg">
        <FontAwesomeIcon icon={faWarning} className="mr-2" />
        Two-factor authentication is <strong>required</strong>.
      </p>
      <AuthenticatorsInput
        value={props.values.authenticators}
        setValue={(auths) => {
          props.setFieldValue("authenticators", auths);
          setTimeout(
            () => props.setFieldTouched("authenticators", true, true),
            0
          );
        }}
        onBlur={props.handleBlur}
      />
    </>
  );

  const renderExemptionsPage = (props: FormikProps<ExemptionListFormData>) => (
    <>
      <FieldArray
        name="organisms"
        render={(arrayHelpers: FieldArrayRenderProps) => (
          <ExemptionTable
            arrayHelpers={arrayHelpers}
            organisms={props.values.organisms}
          />
        )}
      />
    </>
  );

  const renderSuccessPage = (props: FormikProps<ExemptionListFormData>) => (
    <>
      <div className="max-w-prose self-center flex flex-col">
        <p className="mb-4">
          Your request is complete. You can now download a file representing
          your request and send it to the responsible party within your
          organization. This file in itself is <strong>not</strong> a token for
          DNA synthesis; it must be approved first.
        </p>
        <p className="mb-4">
          Once your request is approved, you will receive a token file that you
          can use when submitting DNA synthesis requests for the specified
          organisms to your shipping address.
        </p>
        <PrimaryButton
          type="button"
          onClick={() => {
            const name = makeFileName(props.values.requestor.name) + ".eltr";
            const pem = makeEltrPem(props.values);
            download(pem, "application/x-pem-file", name);
          }}
        >
          Download request file
        </PrimaryButton>
      </div>
    </>
  );

  return (
    <Page title="SecureDNA Exemption Request Form">
      <div className="px-2 w-full max-w-2xl my-8">
        <Formik
          initialValues={emptyExemptionListFormData}
          validateOnChange={false}
          validateOnBlur={true}
          validate={(values) => {
            let errors: FormikErrors<ExemptionListFormData> = {};
            if (!values.requestor.email) {
              errors.requestor ??= {};
              errors.requestor.email = "Required";
            } else if (!emailRegex.test(values.requestor.email)) {
              errors.requestor ??= {};
              errors.requestor.email = "Invalid email address";
            }
            if (values.requestor.orcid) {
              if (!orcidRegex.test(values.requestor.orcid)) {
                errors.requestor ??= {};
                errors.requestor.orcid = "Invalid format (should be 16 digits)";
              } else if (!isOrcidChecksumValid(values.requestor.orcid)) {
                errors.requestor ??= {};
                errors.requestor.orcid =
                  "Invalid check digit (did you make a typo?)";
              }
            }
            if (values.authenticators.length === 0) {
              errors.authenticators = "No authenticators provided";
            }
            let anyShippingErrors = false;
            const shippingErrors = values.shippingAddresses.map((address) => {
              let result: FormikErrors<ShippingAddress> = {};
              if (!address.country) {
                anyShippingErrors = true;
                result.country = "Required";
              }
              return result;
            });
            if (anyShippingErrors) {
              errors.shippingAddresses = shippingErrors;
            }
            let anyOrganismErrors = false;
            const organismErrors: FormikErrors<OrganismWithSource>[] =
              values.organisms.map((organism) => {
                let anySequenceErrors = false;
                const sequenceErrors = organism.sequences.map((si) => {
                  if (
                    "Dna" in si &&
                    (!si.Dna || si.Dna?.records?.length === 0)
                  ) {
                    anySequenceErrors = true;
                    return "Required";
                  } else {
                    return {};
                  }
                });
                if (anySequenceErrors) {
                  return { sequences: sequenceErrors };
                } else {
                  return {};
                }
              });
            if (anyOrganismErrors) {
              errors.organisms = organismErrors;
            }
            return errors;
          }}
          onSubmit={(exemptionList, formik) => {
            setPage(successPageIndex);
            formik.setSubmitting(false);
          }}
        >
          {(props) => (
            <Form className="flex flex-col">
              {[
                renderIntroPage,
                renderShippingPage,
                renderExemptionsPage,
                renderSuccessPage,
              ][page](props)}
              <nav className="flex flex-row justify-center my-8 space-x-2">
                {page > introPageIndex ? (
                  <Button type="button" onClick={() => setPage((n) => n - 1)}>
                    Back
                  </Button>
                ) : undefined}
                {page === successPageIndex && (
                  <PrimaryButton
                    type="button"
                    onClick={() => (window.location.href = "/")}
                  >
                    Restart
                  </PrimaryButton>
                )}
                {page === exemptionsPageIndex && (
                  <PrimaryButton
                    type="button"
                    disabled={
                      !props.dirty || props.errors.organisms !== undefined
                    }
                    onClick={(e) => props.submitForm()}
                  >
                    Submit
                  </PrimaryButton>
                )}
                {page < exemptionsPageIndex && (
                  <PrimaryButton
                    type="button"
                    className={page === introPageIndex ? "flex-1" : ""}
                    disabled={
                      page === shippingPageIndex &&
                      (!props.dirty ||
                        props.errors.requestor !== undefined ||
                        props.errors.authenticators !== undefined ||
                        props.errors.shippingAddresses !== undefined)
                    }
                    onClick={(e) => setPage((n) => n + 1)}
                  >
                    {page === introPageIndex ? "Start" : "Next"}
                  </PrimaryButton>
                )}
              </nav>
            </Form>
          )}
        </Formik>
      </div>
    </Page>
  );
};

export default ExemptionRequestForm;
