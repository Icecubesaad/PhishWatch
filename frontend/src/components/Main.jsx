import React, { useEffect, useRef } from "react";
import Header from "./Header";
import {Link} from "react-router-dom"
const StarField = () => {
  const canvasRef = useRef(null);

  useEffect(() => {
    const STAR_COUNT = (window.innerWidth + window.innerHeight) / 8;
    const STAR_SIZE = 3;
    const STAR_MIN_SCALE = 0.2;
    const OVERFLOW_THRESHOLD = 50;

    const canvas = canvasRef.current;
    const context = canvas.getContext("2d");

    let scale = 1; // device pixel ratio
    let width;
    let height;

    let stars = [];

    let pointerX;
    let pointerY;

    let velocity = { x: 0, y: 0, tx: 0, ty: 0, z: 0.0005 };

    let touchInput = false;

    generate();
    resize();
    step();

    window.onresize = resize;
    canvas.onmousemove = onMouseMove;
    canvas.ontouchmove = onTouchMove;
    canvas.ontouchend = onMouseLeave;
    document.onmouseleave = onMouseLeave;

    function generate() {
      for (let i = 0; i < STAR_COUNT; i++) {
        stars.push({
          x: 0,
          y: 0,
          z: STAR_MIN_SCALE + Math.random() * (1 - STAR_MIN_SCALE),
        });
      }
    }

    function placeStar(star) {
      star.x = Math.random() * width;
      star.y = Math.random() * height;
    }

    function recycleStar(star) {
      let direction = "z";

      let vx = Math.abs(velocity.tx),
        vy = Math.abs(velocity.ty);

      if (vx > 1 && vy > 1) {
        let axis;

        if (vx > vy) {
          axis = Math.random() < Math.abs(velocity.x) / (vx + vy) ? "h" : "v";
        } else {
          axis = Math.random() < Math.abs(velocity.y) / (vx + vy) ? "v" : "h";
        }

        if (axis === "h") {
          direction = velocity.x > 0 ? "l" : "r";
        } else {
          direction = velocity.y > 0 ? "t" : "b";
        }
      }

      star.z = STAR_MIN_SCALE + Math.random() * (1 - STAR_MIN_SCALE);

      if (direction === "z") {
        star.z = 0.1;
        star.x = Math.random() * width;
        star.y = Math.random() * height;
      } else if (direction === "l") {
        star.x = -STAR_SIZE;
        star.y = height * Math.random();
      } else if (direction === "r") {
        star.x = width + STAR_SIZE;
        star.y = height * Math.random();
      } else if (direction === "t") {
        star.x = width * Math.random();
        star.y = -STAR_SIZE;
      } else if (direction === "b") {
        star.x = width * Math.random();
        star.y = height + STAR_SIZE;
      }
    }

    function resize() {
      scale = window.devicePixelRatio || 1;

      width = window.innerWidth * scale;
      height = window.innerHeight * scale;

      canvas.width = width;
      canvas.height = height;

      stars.forEach(placeStar);
    }

    function step() {
      context.clearRect(0, 0, width, height);

      update();
      render();

      requestAnimationFrame(step);
    }

    function update() {
      velocity.tx *= 0.95;
      velocity.ty *= 0.95;

      velocity.x += (velocity.tx - velocity.x) * 0.7;
      velocity.y += (velocity.ty - velocity.y) * 0.7;

      stars.forEach((star) => {
        star.x += velocity.x * star.z;
        star.y += velocity.y * star.z;

        star.x += (star.x - width / 2) * velocity.z * star.z;
        star.y += (star.y - height / 2) * velocity.z * star.z;
        star.z += velocity.z;

        // recycle when out of bounds
        if (
          star.x < -OVERFLOW_THRESHOLD ||
          star.x > width + OVERFLOW_THRESHOLD ||
          star.y < -OVERFLOW_THRESHOLD ||
          star.y > height + OVERFLOW_THRESHOLD
        ) {
          recycleStar(star);
        }
      });
    }

    function render() {
      stars.forEach((star) => {
        context.beginPath();
        context.lineCap = "round";
        context.lineWidth = STAR_SIZE * star.z * scale;
        context.strokeStyle =
          "rgba(255,255,255," + (0.5 + 0.5 * Math.random()) + ")";

        context.beginPath();
        context.moveTo(star.x, star.y);

        var tailX = velocity.x * 2,
          tailY = velocity.y * 2;

        // stroke() wont work on an invisible line
        if (Math.abs(tailX) < 0.1) tailX = 0.5;
        if (Math.abs(tailY) < 0.1) tailY = 0.5;

        context.lineTo(star.x + tailX, star.y + tailY);

        context.stroke();
      });
    }

    function movePointer(x, y) {
      if (typeof pointerX === "number" && typeof pointerY === "number") {
        let ox = x - pointerX,
          oy = y - pointerY;

        velocity.tx = velocity.x + (ox / (8 * scale)) * (touchInput ? -1 : 1);
        velocity.ty = velocity.y + (oy / (8 * scale)) * (touchInput ? -1 : 1);
      }

      pointerX = x;
      pointerY = y;
    }

    function onMouseMove(event) {
      touchInput = false;

      movePointer(event.clientX, event.clientY);
    }

    function onTouchMove(event) {
      touchInput = true;

      movePointer(event.touches[0].clientX, event.touches[0].clientY, true);

      event.preventDefault();
    }

    function onMouseLeave() {
      pointerX = null;
      pointerY = null;
    }
  }, []);

  return (
    <div
      style={{
        position: "relative",
        width: "100%",
        height: "100vh",
        backgroundColor: "#000",
      }}
    >
      <canvas
        ref={canvasRef}
        style={{ position: "absolute", width: "100%", height: "100%" }}
      />
      <div
        style={{
          position: "absolute",
          zIndex: 9999,
          color: "white",
          top: 20,
          left: 20,
          width: "100%",
        }}
      >
        <Header />
        <div className="w-full flex flex-col pl-20 mt-20">
          <h1 className="text-6xl text-white">
            Check URLs Instantly: <br/>Detect Phishing, Stay Safe, Surf Securely.
          </h1>
          <Link to={"/playground"}><button className="w-[200px] mt-10 text-xl h-[60px] bg-white border-white border-[1px] rounded-lg text-black hover:text-white hover:bg-black" style={{transition:"all 300ms"}}>
            explore
          </button>
          </Link>
        </div>
      </div>
    </div>
  );
};

export default StarField;
