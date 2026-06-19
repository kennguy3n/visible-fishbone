import { useIntl } from "react-intl";

// Accessible progress stepper shared by the two Lane B1 onboarding wizards.
// Renders the frozen `.stepper` markup but adds `aria-current="step"` on the
// active step and a visually-hidden status label per step so the progress is
// conveyed to assistive tech, not just by colour and a check glyph.
export function Stepper({
  steps,
  current,
}: {
  steps: readonly string[];
  current: number;
}) {
  const intl = useIntl();
  return (
    <ol className="stepper" aria-label={intl.formatMessage({ id: "b1.stepper.label" })}>
      {steps.map((name, i) => {
        const n = i + 1;
        const state = n === current ? "active" : n < current ? "done" : "todo";
        const statusId =
          state === "active"
            ? "b1.stepper.status.current"
            : state === "done"
              ? "b1.stepper.status.done"
              : "b1.stepper.status.todo";
        return (
          <li
            key={i}
            className={`stepper__step stepper__step--${state}`}
            aria-current={state === "active" ? "step" : undefined}
          >
            <span className="stepper__dot" aria-hidden>
              {state === "done" ? "✓" : n}
            </span>
            <span className="stepper__name">{name}</span>
            <span className="sr-only">
              {" · "}
              {intl.formatMessage({ id: statusId })}
            </span>
            {i < steps.length - 1 && <span className="stepper__bar" aria-hidden />}
          </li>
        );
      })}
    </ol>
  );
}
