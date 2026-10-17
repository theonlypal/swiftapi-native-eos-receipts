import torch

from .common import EOS, require
from .source import non_eos, tensor_bytes


def boundary(module, gate, stock, condition, sign=1.0, auth_status="ORIGINAL_ONLY"):
    require(stock.ndim == 1 and stock.numel() > EOS and torch.isfinite(stock).all().item(), "Invalid stock vector")
    model = module.SeparatedContinuationModel(torch.nn.Identity(), gate)
    ids = torch.tensor([module.condition_tokens(condition)], device=next(gate.parameters()).device)
    learned, state = model.boundary(stock[None], ids, True, sign)
    result = learned[0].clone()
    intervention = "PCCG2_LEARNED_EOS"
    # Reversal is an explicitly isolated causal diagnostic, not an authorization path.
    require(sign == 1.0 or auth_status == "ORIGINAL_ONLY", "Reversal not permitted in authorized execution")
    if auth_status not in ("ORIGINAL_ONLY", "VALID_ALLOW", "VALID_DENY"):
        intervention = "AUTHORIZATION_EOS_VETO"
    elif auth_status == "VALID_DENY" and int(result.argmax()) != EOS:
        intervention = "DENIAL_EOS_VETO"
    if intervention.endswith("VETO"):
        maximum = non_eos(result).float().max()
        veto = maximum + maximum.abs().clamp(min=1)
        result[EOS] = veto.to(result.dtype)
        require(torch.isfinite(result[EOS]).item() and result[EOS] > maximum, "Cannot represent strict EOS veto")
    require(tensor_bytes(non_eos(result)) == tensor_bytes(non_eos(stock)), "Non-EOS mutation")
    return result, float(state[0]), intervention
