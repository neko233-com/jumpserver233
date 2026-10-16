import { useEffect, useRef } from "react";
import { Mesh, Plane, Program, Renderer } from "ogl";

const vertexWebGL1 = /* glsl */ `
precision highp float;
attribute vec3 position;
attribute vec2 uv;
varying vec2 vUv;
void main() {
  vUv = uv;
  gl_Position = vec4(position, 1.0);
}
`;

const vertexWebGL2 = /* glsl */ `#version 300 es
precision highp float;
in vec3 position;
in vec2 uv;
out vec2 vUv;
void main() {
  vUv = uv;
  gl_Position = vec4(position, 1.0);
}
`;

const fragmentBody = /* glsl */ `
  vec2 uv = vUv;
  float t = uTime * 0.35;

  float field = 0.0;
  field += sin((uv.x * 6.0) + t);
  field += sin((uv.y * 5.0) - t * 1.3);
  field += sin((uv.x + uv.y) * 4.0 + t * 0.7);
  field += sin(length(uv - 0.5) * 10.0 - t * 2.0);
  field /= 4.0;

  vec3 deep = vec3(0.05, 0.07, 0.11);
  vec3 blue = vec3(0.12, 0.29, 0.55);
  vec3 violet = vec3(0.35, 0.20, 0.55);

  float m = smoothstep(-1.0, 1.0, field);
  vec3 color = mix(deep, blue, m);
  color = mix(color, violet, pow(m, 3.0) * 0.6);

  // vignette keeps the login card readable
  float vig = smoothstep(1.1, 0.35, length(uv - 0.5));
  color *= vig;
`;

const fragmentWebGL1 = /* glsl */ `
precision highp float;
varying vec2 vUv;
uniform float uTime;
uniform vec2 uResolution;
void main() {
${fragmentBody}
  gl_FragColor = vec4(color, 1.0);
}
`;

const fragmentWebGL2 = /* glsl */ `#version 300 es
precision highp float;
in vec2 vUv;
uniform float uTime;
uniform vec2 uResolution;
out vec4 fragColor;
void main() {
${fragmentBody}
  fragColor = vec4(color, 1.0);
}
`;

/**
 * Fullscreen WebGL shader background rendered with ogl.
 * Degrades to a plain dark background when WebGL is unavailable.
 */
export default function ShaderCanvas({ className }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    canvas.style.display = "";

    let renderer: Renderer | null = null;
    let frame = 0;
    try {
      renderer = new Renderer({
        canvas,
        alpha: false,
        dpr: Math.min(window.devicePixelRatio, 2),
        width: window.innerWidth,
        height: window.innerHeight,
      });
    } catch {
      canvas.style.display = "none";
      return;
    }
    const gl = renderer.gl;
    gl.clearColor(0.05, 0.07, 0.11, 1);

    const geometry = new Plane(gl, { width: 2, height: 2 });
    const webgl2 = renderer.isWebgl2;
    const program = new Program(gl, {
      vertex: webgl2 ? vertexWebGL2 : vertexWebGL1,
      fragment: webgl2 ? fragmentWebGL2 : fragmentWebGL1,
      uniforms: {
        uTime: { value: 0 },
        uResolution: { value: [gl.canvas.width, gl.canvas.height] },
      },
    });
    if (!program.uniformLocations || !program.attributeLocations) {
      canvas.style.display = "none";
      geometry.remove();
      program.remove();
      gl.deleteShader(program.vertexShader);
      gl.deleteShader(program.fragmentShader);
      return;
    }
    const mesh = new Mesh(gl, { geometry, program });

    const resize = () => {
      renderer!.setSize(window.innerWidth, window.innerHeight);
      program.uniforms.uResolution.value = [gl.canvas.width, gl.canvas.height];
    };
    resize();
    window.addEventListener("resize", resize);

    const start = performance.now();
    const loop = (now: number) => {
      if (gl.isContextLost()) return;
      program.uniforms.uTime.value = (now - start) / 1000;
      renderer!.render({ scene: mesh });
      frame = requestAnimationFrame(loop);
    };
    frame = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("resize", resize);
      geometry.remove();
      program.remove();
      gl.deleteShader(program.vertexShader);
      gl.deleteShader(program.fragmentShader);
    };
  }, []);

  return <canvas ref={canvasRef} className={className} aria-hidden />;
}
