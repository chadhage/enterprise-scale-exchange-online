'use strict';

const menuToggle = document.getElementById('menuToggle');
const navigationDrawer = document.getElementById('navigationDrawer');
const drawerClose = document.getElementById('drawerClose');
const drawerBackdrop = document.getElementById('drawerBackdrop');
const navItems = document.querySelectorAll('.nav-item');
const copyCloneUrl = document.getElementById('copyCloneUrl');
const copyStatus = document.getElementById('copyStatus');
let lastFocusedElement = null;

function openDrawer() {
    lastFocusedElement = document.activeElement;
    drawerBackdrop.hidden = false;
    requestAnimationFrame(() => {
        drawerBackdrop.classList.add('is-open');
        navigationDrawer.classList.add('is-open');
        requestAnimationFrame(() => drawerClose.focus());
    });
    navigationDrawer.setAttribute('aria-hidden', 'false');
    menuToggle.setAttribute('aria-expanded', 'true');
    menuToggle.setAttribute('aria-label', 'Close navigation');
    document.body.classList.add('drawer-open');
}

function closeDrawer() {
    drawerBackdrop.classList.remove('is-open');
    navigationDrawer.classList.remove('is-open');
    navigationDrawer.setAttribute('aria-hidden', 'true');
    menuToggle.setAttribute('aria-expanded', 'false');
    menuToggle.setAttribute('aria-label', 'Open navigation');
    document.body.classList.remove('drawer-open');
    window.setTimeout(() => {
        drawerBackdrop.hidden = true;
    }, 300);
    if (lastFocusedElement) {
        lastFocusedElement.focus();
    }
}

function showSection(sectionId, selectedNavItem) {
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });

    const selectedSection = document.getElementById(sectionId);
    if (selectedSection) {
        selectedSection.classList.add('active');
        window.scrollTo(0, 0);
    }

    navItems.forEach(item => item.classList.remove('active'));
    selectedNavItem.classList.add('active');
    closeDrawer();
}

menuToggle.addEventListener('click', () => {
    if (navigationDrawer.classList.contains('is-open')) {
        closeDrawer();
    } else {
        openDrawer();
    }
});

drawerClose.addEventListener('click', closeDrawer);
drawerBackdrop.addEventListener('click', closeDrawer);

navItems.forEach(item => {
    item.addEventListener('click', () => showSection(item.dataset.section, item));
});

document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && navigationDrawer.classList.contains('is-open')) {
        closeDrawer();
    }
});

copyCloneUrl.addEventListener('click', async () => {
    const cloneCommand = 'git clone https://github.com/chadhage/enterprise-scale-exchange-online.git';
    try {
        await navigator.clipboard.writeText(cloneCommand);
        copyStatus.textContent = 'Clone command copied.';
    } catch {
        copyStatus.textContent = 'Copy unavailable. Select the command to copy it.';
    }
});
