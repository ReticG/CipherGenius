"""Unit tests for data models"""

import pytest
from cipher_genius.models.component import Component, ComponentType, Performance, SecurityAnalysis
from cipher_genius.models.requirement import Requirement, SecurityRequirement, TargetPlatform, SchemeType, PlatformType, ResourceLevel


def test_component_creation():
    """Test component model creation"""
    component = Component(
        name="AES-128",
        category=ComponentType.BLOCK_CIPHER,
        performance=Performance(
            software_speed="high",
            memory="low",
            power="medium"
        ),
        security=SecurityAnalysis(
            security_level=128,
            status="secure",
            standardized=True,
        )
    )

    assert component.name == "AES-128"
    assert component.category == ComponentType.BLOCK_CIPHER
    assert component.security.security_level == 128


def test_component_compatibility():
    """Test component compatibility checking"""
    comp1 = Component(
        name="AES",
        category=ComponentType.BLOCK_CIPHER,
        performance=Performance(software_speed="high", memory="low", power="medium"),
        security=SecurityAnalysis(security_level=128),
        compatible_with=["GCM", "CTR"]
    )

    comp2 = Component(
        name="GCM",
        category=ComponentType.MODE_OF_OPERATION,
        performance=Performance(software_speed="high", memory="low", power="medium"),
        security=SecurityAnalysis(security_level=128),
    )

    assert comp1.is_compatible_with(comp2)


def test_component_security_level():
    """Test security level checking"""
    component = Component(
        name="AES-256",
        category=ComponentType.BLOCK_CIPHER,
        performance=Performance(software_speed="high", memory="low", power="medium"),
        security=SecurityAnalysis(security_level=256),
    )

    assert component.meets_security_level(128)
    assert component.meets_security_level(256)
    assert not component.meets_security_level(512)


def test_requirement_creation():
    """Test requirement model creation"""
    requirement = Requirement(
        description="Lightweight encryption for IoT",
        scheme_type=SchemeType.AUTHENTICATED_ENCRYPTION,
        target_platform=TargetPlatform(
            type=PlatformType.IOT_DEVICE,
            resource_level=ResourceLevel.LIGHTWEIGHT,
        ),
        security=SecurityRequirement(
            security_level=128,
        )
    )

    assert requirement.scheme_type == SchemeType.AUTHENTICATED_ENCRYPTION
    assert requirement.target_platform.type == PlatformType.IOT_DEVICE
    assert requirement.security.security_level == 128


def test_requirement_summary():
    """Test requirement summary generation"""
    requirement = Requirement(
        description="Test requirement",
        scheme_type=SchemeType.ENCRYPTION,
        target_platform=TargetPlatform(
            type=PlatformType.SERVER,
            resource_level=ResourceLevel.HIGH_PERFORMANCE,
        ),
        security=SecurityRequirement(security_level=256),
    )

    summary = requirement.get_summary()
    assert "Scheme Type" in summary
    assert "256-bit" in summary
    assert "SERVER" in summary.upper() or "server" in summary
