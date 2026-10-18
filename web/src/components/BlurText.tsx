import { useEffect, useMemo, useRef } from "react";

type Frame = Record<string, string | number>;
type Props = {
  text?: string;
  delay?: number;
  className?: string;
  animateBy?: "words" | "letters";
  direction?: "top" | "bottom";
  threshold?: number;
  rootMargin?: string;
  animationFrom?: Frame;
  animationTo?: Frame[];
  easing?: string;
  stepDuration?: number;
  onAnimationComplete?: () => void;
};

// Retains the React Bits blur/reveal effect using the browser animation engine.
// The complete accessible text stays readable when animation APIs are absent.
export default function BlurText({
  text = "",
  delay = 200,
  className = "",
  animateBy = "words",
  direction = "top",
  threshold = 0.1,
  rootMargin = "0px",
  animationFrom,
  animationTo,
  easing = "linear",
  stepDuration = 0.35,
  onAnimationComplete,
}: Props) {
  const root = useRef<HTMLSpanElement>(null);
  const segments = useMemo(
    () =>
      animateBy === "words"
        ? text.split(/(\s+)/).filter(Boolean)
        : typeof Intl.Segmenter === "function"
          ? Array.from(
              new Intl.Segmenter(undefined, { granularity: "grapheme" }).segment(text),
              (s) => s.segment,
            )
          : Array.from(text),
    [text, animateBy],
  );
  useEffect(() => {
    const node = root.current;
    if (!node) return;
    const children = Array.from(node.querySelectorAll<HTMLElement>("[data-blur-segment]"));
    const motion = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    let cancelled = false,
      started = false,
      completed = false;
    let observer: IntersectionObserver | undefined;
    const animations: Animation[] = [];
    const finish = () => {
      if (!cancelled && !completed) {
        completed = true;
        onAnimationComplete?.();
      }
    };
    const stop = () => {
      for (const a of animations) a.cancel();
      for (const el of children) el.style.willChange = "";
    };
    const play = () => {
      if (started || cancelled) return;
      started = true;
      observer?.disconnect();
      if (motion?.matches || typeof node.animate !== "function") {
        finish();
        return;
      }
      const from = animationFrom ?? {
        filter: "blur(10px)",
        opacity: 0,
        y: direction === "top" ? -50 : 50,
      };
      const to = animationTo ?? [
        { filter: "blur(5px)", opacity: 0.5, y: direction === "top" ? 5 : -5 },
        { filter: "blur(0px)", opacity: 1, y: 0 },
      ];
      const frames: Keyframe[] = [from, ...to].map((v) => {
        const { y, ...css } = v;
        return {
          ...css,
          ...(y === undefined
            ? {}
            : { transform: typeof y === "number" ? `translateY(${y}px)` : `translateY(${y})` }),
        };
      });
      try {
        children.forEach((el, i) => {
          el.style.willChange = "transform, filter, opacity";
          animations.push(
            el.animate(frames, {
              duration: Math.max(0, stepDuration * to.length * 1000),
              delay: i * Math.max(0, delay),
              fill: "backwards",
              easing,
            }),
          );
        });
        void Promise.all(animations.map((a) => a.finished)).then(
          () => {
            stop();
            finish();
          },
          () => undefined,
        );
      } catch {
        stop();
        finish();
      }
    };
    const reduce = () => {
      if (motion?.matches) {
        observer?.disconnect();
        stop();
        finish();
      }
    };
    motion?.addEventListener("change", reduce);
    if (motion?.matches || typeof IntersectionObserver !== "function") play();
    else {
      observer = new IntersectionObserver(
        (entries) => {
          if (entries.some((e) => e.isIntersecting)) play();
        },
        { threshold, rootMargin },
      );
      observer.observe(node);
    }
    return () => {
      cancelled = true;
      observer?.disconnect();
      motion?.removeEventListener("change", reduce);
      stop();
    };
  }, [
    segments,
    delay,
    direction,
    threshold,
    rootMargin,
    animationFrom,
    animationTo,
    easing,
    stepDuration,
    onAnimationComplete,
  ]);
  return (
    <span ref={root} className={className} style={{ display: "inline-flex", flexWrap: "wrap" }}>
      <span
        style={{
          position: "absolute",
          width: 1,
          height: 1,
          overflow: "hidden",
          clipPath: "inset(50%)",
          whiteSpace: "nowrap",
        }}
      >
        {text}
      </span>
      {segments.map((part, i) => (
        <span
          key={i}
          aria-hidden="true"
          data-blur-segment=""
          style={{ display: "inline-block", whiteSpace: "pre" }}
        >
          {part}
        </span>
      ))}
    </span>
  );
}
