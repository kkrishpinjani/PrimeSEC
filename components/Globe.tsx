import { useEffect, useRef } from "react";
import * as THREE from "three";
import { feature } from "topojson-client";
import type { Topology, GeometryCollection } from "topojson-specification";
import landTopology from "world-atlas/land-110m.json";

/**
 * WebGL globe on real geography (Natural Earth 1:110m land via world-atlas). Markers and arcs are
 * drawn only for the data passed in: nothing is invented. With no markers it is just the Earth.
 */
export type GlobeMarker = { lat: number; lon: number; label: string; count: number; severity: "high" | "normal" };
export type GlobeHome = { lat: number; lon: number; label: string };

const R = 1.5;
const TEAL = new THREE.Color("#2dd4bf");
const CYAN = new THREE.Color("#7dd3fc");
const ALERT = new THREE.Color("#ff6b81");

function latLon(lat: number, lon: number, r = R): THREE.Vector3 {
  const phi = ((90 - lat) * Math.PI) / 180;
  const theta = ((lon + 180) * Math.PI) / 180;
  return new THREE.Vector3(-r * Math.sin(phi) * Math.cos(theta), r * Math.cos(phi), r * Math.sin(phi) * Math.sin(theta));
}

/** Rasterises real land polygons to an equirectangular bitmap and returns a lat/lon -> land test. */
function buildLandMask(): (lat: number, lon: number) => boolean {
  const W = 1024, H = 512;
  const canvas = document.createElement("canvas");
  canvas.width = W; canvas.height = H;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) return () => false;
  const topo = landTopology as unknown as Topology;
  const land = feature(topo, topo.objects.land as GeometryCollection) as unknown as GeoJSON.FeatureCollection | GeoJSON.Feature;
  const geometries = land.type === "FeatureCollection" ? land.features.map((f) => f.geometry) : [land.geometry];
  ctx.fillStyle = "#fff";
  for (const g of geometries) {
    if (!g) continue;
    const polygons = g.type === "Polygon" ? [g.coordinates] : g.type === "MultiPolygon" ? g.coordinates : [];
    for (const rings of polygons) {
      ctx.beginPath();
      for (const ring of rings) {
        ring.forEach(([lon, lat], i) => {
          const x = ((lon + 180) / 360) * W, y = ((90 - lat) / 180) * H;
          if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        });
        ctx.closePath();
      }
      ctx.fill("evenodd");
    }
  }
  const px = ctx.getImageData(0, 0, W, H).data;
  return (lat, lon) => {
    const x = Math.min(W - 1, Math.max(0, Math.floor(((lon + 180) / 360) * W)));
    const y = Math.min(H - 1, Math.max(0, Math.floor(((90 - lat) / 180) * H)));
    return px[(y * W + x) * 4 + 3] > 127;
  };
}

const dotVert = /* glsl */ `
  attribute float aSize; attribute float aAlpha;
  varying float vAlpha;
  void main(){
    vAlpha = aAlpha;
    vec4 mv = modelViewMatrix * vec4(position,1.0);
    gl_PointSize = aSize * (260.0 / -mv.z);
    gl_Position = projectionMatrix * mv;
  }`;
const dotFrag = /* glsl */ `
  uniform vec3 uColor; varying float vAlpha;
  void main(){
    float d = length(gl_PointCoord - 0.5);
    if(d > 0.5) discard;
    gl_FragColor = vec4(uColor, vAlpha * smoothstep(0.5, 0.15, d));
  }`;
const atmoVert = /* glsl */ `
  varying vec3 vN;
  void main(){ vN = normalize(normalMatrix * normal); gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.0); }`;
const atmoFrag = /* glsl */ `
  varying vec3 vN;
  void main(){ float i = pow(clamp(-dot(vN, vec3(0.0,0.0,1.0)) * 1.7, 0.0, 1.0), 3.0); gl_FragColor = vec4(0.18,0.83,0.75,1.0) * i * 0.55; }`;

export default function Globe({ className, markers = [], home }: { className?: string; markers?: GlobeMarker[]; home?: GlobeHome | null }) {
  const mountRef = useRef<HTMLDivElement>(null);
  const dataKey = JSON.stringify({ markers, home });

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    } catch {
      return; // WebGL unavailable: the CSS glow behind the canvas remains.
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    mount.appendChild(renderer.domElement);
    renderer.domElement.style.cssText = "width:100%;height:100%;display:block";

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 50);
    camera.position.set(0, 0, 5.7);

    const world = new THREE.Group();
    world.rotation.x = 0.42;
    scene.add(world);
    const spin = new THREE.Group();
    world.add(spin);

    // occluding core so back-side dots are hidden
    const core = new THREE.Mesh(
      new THREE.SphereGeometry(R * 0.995, 64, 64),
      new THREE.MeshBasicMaterial({ color: "#031615" })
    );
    world.add(core);

    // atmosphere
    const atmo = new THREE.Mesh(
      new THREE.SphereGeometry(R * 1.16, 64, 64),
      new THREE.ShaderMaterial({
        vertexShader: atmoVert, fragmentShader: atmoFrag,
        blending: THREE.AdditiveBlending, side: THREE.BackSide, transparent: true, depthWrite: false
      })
    );
    scene.add(atmo);

    // dotted surface: Fibonacci lattice, land (bright) vs ocean (faint)
    const N = 11000;
    const land: number[] = [], ocean: number[] = [];
    const golden = Math.PI * (3 - Math.sqrt(5));
    const tmp = new THREE.Vector3();
    const isLandAt = buildLandMask();
    for (let i = 0; i < N; i++) {
      const y = 1 - (i / (N - 1)) * 2;
      const rr = Math.sqrt(1 - y * y);
      const th = golden * i;
      tmp.set(Math.cos(th) * rr, y, Math.sin(th) * rr);
      // inverse of latLon(): sphere point -> geographic lat/lon, then look up real land
      const lat = (Math.asin(y) * 180) / Math.PI;
      let lon = (Math.atan2(tmp.z, -tmp.x) * 180) / Math.PI - 180;
      if (lon < -180) lon += 360;
      const isLand = isLandAt(lat, lon);
      (isLand ? land : ocean).push(tmp.x * R, tmp.y * R, tmp.z * R);
    }
    const makeDots = (pts: number[], color: THREE.Color, size: number, alpha: number) => {
      const g = new THREE.BufferGeometry();
      g.setAttribute("position", new THREE.Float32BufferAttribute(pts, 3));
      const n = pts.length / 3;
      g.setAttribute("aSize", new THREE.Float32BufferAttribute(new Array(n).fill(size), 1));
      g.setAttribute("aAlpha", new THREE.Float32BufferAttribute(new Array(n).fill(alpha), 1));
      return new THREE.Points(g, new THREE.ShaderMaterial({
        vertexShader: dotVert, fragmentShader: dotFrag, transparent: true, depthWrite: false,
        uniforms: { uColor: { value: color } }
      }));
    };
    spin.add(makeDots(land, TEAL, 0.07, 0.95));
    spin.add(makeDots(ocean, new THREE.Color("#0f766e"), 0.038, 0.4));

    // network lattice shell
    const lattice = new THREE.LineSegments(
      new THREE.WireframeGeometry(new THREE.IcosahedronGeometry(R * 1.18, 1)),
      new THREE.LineBasicMaterial({ color: "#5eead4", transparent: true, opacity: 0.16 })
    );
    world.add(lattice);
    const latticeNodes = new THREE.Points(
      new THREE.IcosahedronGeometry(R * 1.18, 1),
      new THREE.PointsMaterial({ color: "#a7f3d0", size: 0.05, transparent: true, opacity: 0.9 })
    );
    world.add(latticeNodes);

    // Real data only: one beacon per geolocated alert source, an arc to the SOC home when known.
    const pulses: { mesh: THREE.Mesh; curve: THREE.QuadraticBezierCurve3; t: number; speed: number }[] = [];
    const rings: THREE.Mesh[] = [];
    const addBeacon = (lat: number, lon: number, color: THREE.Color | string, phase: number, size: number) => {
      const p = latLon(lat, lon, R * 1.004);
      const dot = new THREE.Mesh(new THREE.SphereGeometry(size, 10, 10), new THREE.MeshBasicMaterial({ color }));
      dot.position.copy(p);
      spin.add(dot);
      const ring = new THREE.Mesh(
        new THREE.RingGeometry(0.04, 0.052, 32),
        new THREE.MeshBasicMaterial({ color: TEAL, transparent: true, opacity: 0.8, side: THREE.DoubleSide, depthWrite: false })
      );
      ring.position.copy(p);
      ring.lookAt(p.clone().multiplyScalar(2));
      ring.userData.phase = phase;
      spin.add(ring);
      rings.push(ring);
      return p;
    };
    const homePos = home ? addBeacon(home.lat, home.lon, "#ffffff", 0, 0.04) : null;
    markers.forEach((m, i) => {
      const hot = m.severity === "high";
      const pa = addBeacon(m.lat, m.lon, hot ? ALERT : "#ccfbf1", (i + 1) / (markers.length + 1), 0.03);
      if (!homePos) return;
      const mid = pa.clone().add(homePos).multiplyScalar(0.5);
      mid.setLength(R + pa.distanceTo(homePos) * 0.42);
      const curve = new THREE.QuadraticBezierCurve3(pa, mid, homePos);
      spin.add(new THREE.Line(
        new THREE.BufferGeometry().setFromPoints(curve.getPoints(64)),
        new THREE.LineBasicMaterial({ color: hot ? ALERT : CYAN, transparent: true, opacity: hot ? 0.55 : 0.4 })
      ));
      const pulse = new THREE.Mesh(new THREE.SphereGeometry(0.028, 10, 10), new THREE.MeshBasicMaterial({ color: hot ? ALERT : "#ffffff" }));
      spin.add(pulse);
      pulses.push({ mesh: pulse, curve, t: (i * 0.17) % 1, speed: 0.12 + (i % 5) * 0.035 });
    });
    // start facing the SOC home, or the Americas/Atlantic when there is none
    spin.rotation.y = home ? -((home.lon + 180) * Math.PI) / 180 + Math.PI / 2 : -1.6;

    // sizing
    const resize = () => {
      const w = mount.clientWidth || 1, h = mount.clientHeight || 1;
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.position.z = 5.7 * Math.max(1, 1.05 / camera.aspect);
      camera.updateProjectionMatrix();
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(mount);

    // pointer parallax
    const target = { x: 0, y: 0 };
    const onMove = (e: PointerEvent) => {
      const r = mount.getBoundingClientRect();
      target.x = ((e.clientX - r.left) / r.width - 0.5) * 2;
      target.y = ((e.clientY - r.top) / r.height - 0.5) * 2;
    };
    window.addEventListener("pointermove", onMove);

    let raf = 0;
    let visible = true;
    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting; }, { threshold: 0 });
    io.observe(mount);
    const clock = new THREE.Clock();
    const pos = new THREE.Vector3();

    const frame = () => {
      raf = requestAnimationFrame(frame);
      if (!visible) return;
      const dt = Math.min(clock.getDelta(), 0.05);
      const t = clock.elapsedTime;
      if (!reduced) {
        spin.rotation.y += dt * 0.12;
        lattice.rotation.y -= dt * 0.05;
        latticeNodes.rotation.y = lattice.rotation.y;
        pulses.forEach((p) => {
          p.t = (p.t + dt * p.speed) % 1;
          p.curve.getPoint(p.t, pos);
          p.mesh.position.copy(pos);
        });
        rings.forEach((r) => {
          const k = (t * 0.6 + (r.userData.phase as number)) % 1;
          r.scale.setScalar(1 + k * 3.2);
          (r.material as THREE.MeshBasicMaterial).opacity = 0.8 * (1 - k);
        });
      }
      world.rotation.y += (target.x * 0.35 - world.rotation.y) * 0.04;
      world.rotation.x += (0.42 + target.y * 0.18 - world.rotation.x) * 0.04;
      renderer.render(scene, camera);
    };
    frame();

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      io.disconnect();
      window.removeEventListener("pointermove", onMove);
      scene.traverse((o) => {
        const m = o as THREE.Mesh;
        m.geometry?.dispose?.();
        const mat = m.material as THREE.Material | THREE.Material[] | undefined;
        if (Array.isArray(mat)) mat.forEach((x) => x.dispose()); else mat?.dispose?.();
      });
      renderer.dispose();
      renderer.domElement.remove();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dataKey]);

  return <div ref={mountRef} className={className} aria-hidden="true" />;
}
