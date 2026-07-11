(() => {
    const body = document.body;
    const preloader = document.getElementById("preloader");
    let preloaderHidden = false;

    if (body) {
        body.classList.add("loading");
    }

    const hidePreloader = () => {
        if (preloaderHidden) {
            return;
        }
        preloaderHidden = true;

        if (body) {
            body.classList.remove("loading");
            body.classList.add("loaded");
        }

        if (preloader) {
            window.setTimeout(() => {
                preloader.remove();
            }, 520);
        }
    };

    window.addEventListener("load", hidePreloader, { once: true });
    window.setTimeout(hidePreloader, 4000);
})();

document.addEventListener("DOMContentLoaded", () => {
    const topbarInner = document.querySelector(".topbar-inner");
    const navToggle = document.querySelector(".nav-toggle");
    const navLinks = document.querySelector(".nav-links");

    if (topbarInner && navToggle && navLinks) {
        const closeMenu = () => {
            topbarInner.classList.remove("menu-open");
            navToggle.setAttribute("aria-expanded", "false");
        };

        navToggle.addEventListener("click", () => {
            const isOpen = topbarInner.classList.toggle("menu-open");
            navToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
        });

        navLinks.querySelectorAll("a").forEach((link) => {
            link.addEventListener("click", closeMenu);
        });

        window.addEventListener("resize", () => {
            if (window.innerWidth > 700) {
                closeMenu();
            }
        });

        document.addEventListener("click", (event) => {
            if (!topbarInner.contains(event.target) && topbarInner.classList.contains("menu-open")) {
                closeMenu();
            }
        });
    }

    const animatedItems = document.querySelectorAll(
        ".hero, .section, .page-header, .card-block, .stat-box, .action-card, .vacancy-card, .job-card, .dashboard-banner"
    );

    const selectAll = document.getElementById("select-all-applications");
    const rowChecks = document.querySelectorAll(".bulk-application-check");
    if (selectAll && rowChecks.length) {
        selectAll.addEventListener("change", () => {
            rowChecks.forEach((check) => {
                check.checked = selectAll.checked;
            });
        });
        rowChecks.forEach((check) => {
            check.addEventListener("change", () => {
                if (!check.checked) {
                    selectAll.checked = false;
                    return;
                }
                const allChecked = Array.from(rowChecks).every((item) => item.checked);
                selectAll.checked = allChecked;
            });
        });
    }

    const copyButtons = document.querySelectorAll(".copy-btn");
    copyButtons.forEach((button) => {
        button.addEventListener("click", async () => {
            const targetId = button.getAttribute("data-copy-target");
            const target = targetId ? document.getElementById(targetId) : null;
            const text = target ? target.textContent.trim() : "";
            if (!text) {
                return;
            }
            try {
                await navigator.clipboard.writeText(text);
                const original = button.textContent;
                button.textContent = "Copied";
                window.setTimeout(() => {
                    button.textContent = original;
                }, 1200);
            } catch (_error) {
                // Fallback: keep quiet if clipboard API is unavailable.
            }
        });
    });

    const imageInput = document.getElementById("profile-image-input");
    const cropCanvas = document.getElementById("profile-crop-preview");
    const cropWrap = document.getElementById("crop-preview-wrap");
    const zoomSlider = document.getElementById("profile-image-zoom");
    if (imageInput && cropCanvas && cropWrap && zoomSlider) {
        const ctx = cropCanvas.getContext("2d");
        const previewImage = new Image();
        let imageLoaded = false;

        const drawPreview = () => {
            if (!imageLoaded) {
                return;
            }
            const canvasSize = cropCanvas.width;
            const zoom = Number(zoomSlider.value || "1");
            const srcWidth = previewImage.naturalWidth / zoom;
            const srcHeight = previewImage.naturalHeight / zoom;
            const srcSize = Math.min(srcWidth, srcHeight);
            const sx = (previewImage.naturalWidth - srcSize) / 2;
            const sy = (previewImage.naturalHeight - srcSize) / 2;
            ctx.clearRect(0, 0, canvasSize, canvasSize);
            ctx.drawImage(previewImage, sx, sy, srcSize, srcSize, 0, 0, canvasSize, canvasSize);
        };

        imageInput.addEventListener("change", () => {
            const file = imageInput.files && imageInput.files[0];
            if (!file) {
                cropWrap.classList.remove("visible");
                return;
            }
            if (!file.type.startsWith("image/")) {
                cropWrap.classList.remove("visible");
                return;
            }
            const reader = new FileReader();
            reader.onload = (event) => {
                previewImage.onload = () => {
                    imageLoaded = true;
                    zoomSlider.value = "1";
                    cropWrap.classList.add("visible");
                    drawPreview();
                };
                previewImage.src = String(event.target?.result || "");
            };
            reader.readAsDataURL(file);
        });

        zoomSlider.addEventListener("input", drawPreview);
    }

    if (!animatedItems.length) {
        return;
    }

    animatedItems.forEach((element) => {
        element.setAttribute("data-animate", "true");
    });

    const observer = new IntersectionObserver(
        (entries, obs) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    entry.target.classList.add("in-view");
                    obs.unobserve(entry.target);
                }
            });
        },
        {
            threshold: 0.12,
            rootMargin: "0px 0px -30px 0px",
        }
    );

    animatedItems.forEach((element) => observer.observe(element));
});
