# Contributing to Enhanced HTTP Anomaly Detection

Thank you for your interest in contributing to the Enhanced HTTP Anomaly Detection system! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [How to Contribute](#how-to-contribute)
4. [Development Setup](#development-setup)
5. [Coding Standards](#coding-standards)
6. [Testing](#testing)
7. [Documentation](#documentation)
8. [Pull Request Process](#pull-request-process)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please be respectful and professional in all interactions.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/Dask-AD.git
   cd Dask-AD/Enhanced-HTTP-Anomaly-Detection
   ```
3. Add the upstream repository as a remote:
   ```bash
   git remote add upstream https://github.com/original-repo/Dask-AD.git
   ```

## How to Contribute

### Reporting Bugs

- Check if the bug has already been reported in the Issues section
- If not, create a new issue with:
  - Clear, descriptive title
  - Steps to reproduce
  - Expected behavior
  - Actual behavior
  - System information (OS, Python version, etc.)
  - Relevant logs or error messages

### Suggesting Enhancements

- Check if the enhancement has already been suggested
- Create a new issue with:
  - Clear description of the enhancement
  - Use cases and benefits
  - Potential implementation approach

### Code Contributions

1. **Choose an Issue**: Look for issues labeled `good first issue` or `help wanted`
2. **Comment on the Issue**: Let others know you're working on it
3. **Create a Branch**: 
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. **Make Changes**: Implement your feature or fix
5. **Test**: Ensure all tests pass
6. **Commit**: Use clear, descriptive commit messages
7. **Push**: Push to your fork
8. **Create PR**: Submit a pull request to the main repository

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Docker (optional, for containerized development)
- Git

### Environment Setup

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

3. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

### Running the Development Server

```bash
python ai-detection-engine/enhanced_detector.py --mode detect --data sample_data.log
```

## Coding Standards

### Python Style Guide

We follow PEP 8 with the following specifications:
- Line length: 100 characters
- Use type hints where appropriate
- Docstrings for all public functions and classes

### Code Formatting

Use `black` for automatic formatting:
```bash
black .
```

### Linting

Use `flake8` for linting:
```bash
flake8 .
```

### Type Checking

Use `mypy` for type checking:
```bash
mypy .
```

### Example Code Style

```python
from typing import Dict, List, Optional

def extract_features(
    data: pd.DataFrame,
    feature_list: Optional[List[str]] = None
) -> Dict[str, float]:
    """
    Extract features from input data.
    
    Args:
        data: Input DataFrame containing log entries
        feature_list: Optional list of features to extract
        
    Returns:
        Dictionary mapping feature names to values
        
    Raises:
        ValueError: If data is empty or invalid
    """
    if data.empty:
        raise ValueError("Input data cannot be empty")
    
    # Implementation here
    return features
```

## Testing

### Running Tests

Run all tests:
```bash
pytest
```

Run with coverage:
```bash
pytest --cov=enhanced_detector tests/
```

Run specific test file:
```bash
pytest tests/test_feature_extraction.py
```

### Writing Tests

- Place tests in the `tests/` directory
- Name test files with `test_` prefix
- Use descriptive test function names
- Include both positive and negative test cases

Example test:
```python
import pytest
from enhanced_detector import EnhancedAnomalyDetector

def test_feature_extraction():
    """Test that features are correctly extracted from log data."""
    detector = EnhancedAnomalyDetector()
    sample_data = pd.DataFrame({
        'path': ['/login', '/admin/config'],
        'status': [200, 404]
    })
    
    features = detector.extract_features(sample_data)
    
    assert 'path_entropy' in features.columns
    assert len(features) == len(sample_data)
```

### Test Coverage

Maintain minimum test coverage of 80% for new code.

## Documentation

### Docstrings

Use Google-style docstrings:
```python
def function(arg1: str, arg2: int) -> bool:
    """
    Brief description of function.
    
    Longer description if needed.
    
    Args:
        arg1: Description of arg1
        arg2: Description of arg2
        
    Returns:
        Description of return value
        
    Raises:
        ValueError: When validation fails
    """
```

### README Updates

Update the README.md when:
- Adding new features
- Changing installation process
- Modifying configuration options
- Adding new dependencies

### API Documentation

If modifying the API, update the API documentation in `docs/api.md`.

## Pull Request Process

### Before Submitting

1. **Update from upstream**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run tests**:
   ```bash
   pytest
   ```

3. **Check code quality**:
   ```bash
   black .
   flake8 .
   mypy .
   ```

4. **Update documentation** if needed

### PR Guidelines

#### Title
Use a clear, descriptive title:
- `feat: Add XSS detection feature`
- `fix: Correct entropy calculation`
- `docs: Update installation instructions`
- `test: Add tests for HTTP parser`

#### Description
Include in your PR description:
- What changes were made
- Why the changes were necessary
- Any breaking changes
- Related issue numbers

#### Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## Testing
- [ ] All tests pass
- [ ] New tests added for new functionality
- [ ] Test coverage maintained or improved

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings
- [ ] Changes are backward compatible

## Related Issues
Fixes #123
```

### Review Process

1. At least one maintainer must review the PR
2. All CI checks must pass
3. Address review comments promptly
4. Squash commits if requested

## Performance Considerations

When contributing performance improvements:
1. Include benchmark results
2. Test with large datasets (>100k log entries)
3. Profile memory usage
4. Consider edge cases

## Security Considerations

- Never commit credentials or API keys
- Sanitize all user inputs
- Follow OWASP guidelines for web security
- Report security vulnerabilities privately

## Questions?

If you have questions, please:
1. Check the documentation
2. Search existing issues
3. Ask in the discussions section
4. Contact maintainers

## Recognition

Contributors will be recognized in:
- The CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for contributing to Enhanced HTTP Anomaly Detection!