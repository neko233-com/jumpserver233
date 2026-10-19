import { useEffect, useRef } from "react";
import { Program, Renderer } from "ogl";

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

  vec3 deep = uBase;
  vec3 blue = uAccent;
  vec3 violet = uHighlight;

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
uniform vec3 uBase;
uniform vec3 uAccent;
uniform vec3 uHighlight;
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
uniform vec3 uBase;
uniform vec3 uAccent;
uniform vec3 uHighlight;
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
export default function ShaderCanvas({
  className,
  background = "#0d1117",
  accent = "#2f81f7",
}: {
  className?: string;
  background?: string;
  accent?: string;
}) {
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

    const webgl2 = renderer.isWebgl2;
    const rgb = (hex: string) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
    const original = background === "#0d1117" && accent === "#2f81f7";
    const tint = rgb(accent);
    const program = new Program(gl, {
      vertex: webgl2 ? vertexWebGL2 : vertexWebGL1,
      fragment: webgl2 ? fragmentWebGL2 : fragmentWebGL1,
      depthTest: false,
      depthWrite: false,
      uniforms: {
        uTime: { value: 0 },
        uResolution: { value: [gl.canvas.width, gl.canvas.height] },
        uBase: { value: original ? [0.05, 0.07, 0.11] : rgb(background) },
        uAccent: { value: original ? [0.12, 0.29, 0.55] : tint.map((v) => v * 0.55) },
        uHighlight: { value: original ? [0.35, 0.2, 0.55] : tint.map((v) => v * 0.7 + 0.05) },
      },
    });
    if (!program.uniformLocations || !program.attributeLocations) {
      canvas.style.display = "none";
      program.remove();
      gl.deleteShader(program.vertexShader);
      gl.deleteShader(program.fragmentShader);
      return;
    }
    // A screen background needs one triangle, without a scene graph or matrices.
    const buffer = gl.createBuffer();
    if (!buffer) {
      canvas.style.display = "none";
      program.remove();
      gl.deleteShader(program.vertexShader);
      gl.deleteShader(program.fragmentShader);
      return;
    }
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 0, 0, 3, -1, 2, 0, -1, 3, 0, 2]),
      gl.STATIC_DRAW,
    );
    for (const [name, offset] of [
      ["position", 0],
      ["uv", 8],
    ] as const) {
      const index = gl.getAttribLocation(program.program, name);
      if (index >= 0) {
        gl.enableVertexAttribArray(index);
        gl.vertexAttribPointer(index, 2, gl.FLOAT, false, 16, offset);
      }
    }

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
      renderer!.setViewport(gl.canvas.width, gl.canvas.height);
      program.use();
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      frame = requestAnimationFrame(loop);
    };
    frame = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("resize", resize);
      gl.deleteBuffer(buffer);
      program.remove();
      gl.deleteShader(program.vertexShader);
      gl.deleteShader(program.fragmentShader);
    };
  }, [background, accent]);

  return <canvas ref={canvasRef} className={className} aria-hidden />;
}
