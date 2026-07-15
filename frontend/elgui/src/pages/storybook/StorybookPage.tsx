/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import {
  AuthFeedback,
  Button,
  Card,
  Input,
  LinkButton,
  OrganismCard,
  PrimaryButton,
  RemoveButton,
  ScreeningVisualization,
} from "@securedna/frontend_common";
import { Form, Formik } from "formik";
import { useParams } from "react-router-dom";
import { FormInput } from "src/components/FormInput";
import { ScreeningResult } from "src/components/ScreeningCard";
import {
  exampleAuthFeedback,
  exampleOrganism,
  exampleScreeningResult,
} from "./data";

export default function StorybookPage() {
  const { page } = useParams();
  switch (page) {
    case "typography":
      return (
        <div>
          <h1>Heading 1</h1>
          <h2>Heading 2</h2>
          <p>
            Lorem Ipsum is simply dummy text of the printing and typesetting
            industry. Lorem Ipsum has been the industry's standard dummy text
            ever since the 1500s, when an unknown printer took a galley of type
            and scrambled it to make a type specimen book. It has survived not
            only five centuries, but also the leap into electronic typesetting,
            remaining essentially unchanged.
          </p>
          <p>
            It was popularised in the 1960s with the release of Letraset sheets
            containing Lorem Ipsum passages, and more recently with desktop
            publishing software like Aldus PageMaker including versions of Lorem
            Ipsum.
          </p>
        </div>
      );
    case "form":
      return (
        <div>
          <h1>Buttons</h1>
          <div className="flex space-x-2">
            <Button type="button">Secondary button</Button>
            <PrimaryButton type="button">Primary button</PrimaryButton>
            <LinkButton type="button">Link button</LinkButton>
            <RemoveButton className="w-6" type="button" />
          </div>
          <h1>Inputs</h1>
          <Input type="text" placeholder="Text input" />
          <h2>Inside form:</h2>
          <Formik initialValues={{}} onSubmit={(values) => console.log(values)}>
            <Form className="flex flex-col">
              <FormInput
                label="Input with suggestions"
                suggestions={["Apple", "Banana", "Cherry", "Vanilla"]}
                name="flavor"
              />

              <FormInput
                label="Digit-pattern input"
                name="orcid"
                placeholder="(000)-000-000"
                digitPattern={{
                  pattern: "(000)-000-000",
                  digitRegex: /[0-9X]/gi,
                  transform: "uppercase",
                }}
              />
            </Form>
          </Formik>
        </div>
      );
    case "card": {
      return (
        <div>
          <h1>Cards</h1>
          <Card>Plain card</Card>
          <Card flavor="primary">Primary color card</Card>
          <Card flavor="warn">Warning card</Card>
          <h2>Organism card</h2>
          <OrganismCard organism={exampleOrganism} />
        </div>
      );
    }
    case "screening": {
      return (
        <div>
          <h1>Screening</h1>
          <ScreeningVisualization
            result={{ synthesis_permission: "granted" }}
          />
          <ScreeningVisualization
            result={{
              synthesis_permission: "denied",
              hits_by_record: [],
              warnings: [
                {
                  diagnostic: "Warning diagnostic",
                  additional_info: "Warning additional info",
                },
              ],
            }}
          />
          <ScreeningResult
            name={"Safe organism"}
            sequence={"ACTGACTG"}
            result={{ synthesis_permission: "granted" }}
          />
          <ScreeningResult
            name={"Denied with warning"}
            sequence={"ACTGACTG"}
            result={{
              synthesis_permission: "denied",
              hits_by_record: [],
              warnings: [
                {
                  diagnostic: "Warning diagnostic",
                  additional_info: "Warning additional info",
                },
              ],
            }}
          />
          <ScreeningResult
            name={"Denied with error"}
            sequence={"ACTGACTG"}
            result={{
              synthesis_permission: "denied",
              hits_by_record: [],
              errors: [
                {
                  diagnostic: "Error diagnostic",
                  additional_info: "Error additional info",
                },
              ],
            }}
          />
          <ScreeningResult
            name={"Hazard"}
            sequence={"ACTG".repeat(101)}
            result={exampleScreeningResult}
          />
        </div>
      );
    }
    case "auth-feedback":
      return (
        <div>
          <h1>Auth feedback</h1>
          {exampleAuthFeedback.map(({ label, value }) => (
            <div key={label}>
              <h2>{label}</h2>
              <Card flavor="primary">
                <AuthFeedback feedback={value} noun={"token"} />
              </Card>
            </div>
          ))}
        </div>
      );
    default:
      return <code>Unknown storybook page: {page}</code>;
  }
}
